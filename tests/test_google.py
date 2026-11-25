"""Offline tests for the anti-block Google client."""

import random
import unittest

from specter.google import (
    GoogleScraper,
    cooldown_remaining,
    google_url,
    is_wall,
    parse_results,
    reset_state,
)
from specter.models import BLOCKED, FOUND, INFO

RESULTS_PAGE = """
<div class="g">
  <a href="/url?q=https://jvns.ca/&amp;sa=U"><h3>Julia Evans</h3></a>
  <div class="VwiC3b">A blog about programming and debugging.</div>
</div>
<div class="g">
  <a href="https://www.google.com/preferences"><h3>Search settings</h3></a>
</div>
<div class="g">
  <a href="/url?q=https://jvns.ca/&amp;sa=U"><h3>Julia Evans again</h3></a>
</div>
"""

WALL_PAGE = "<html><body><noscript>Please click here if you are not redirected</noscript><a href='/httpservice/retry/enablejs'>enablejs</a></body></html>"


class FakeResponse:
    def __init__(self, text: str = "", status: int = 200) -> None:
        self.text = text
        self.status = status
        self.ok = 200 <= status < 300
        self.blocked = status in (403, 429)


class FakeGet:
    """Records calls and answers through a handler(url, params, headers)."""

    def __init__(self, handler) -> None:
        self.handler = handler
        self.calls: list[tuple[str, dict, dict]] = []

    def __call__(self, url, params, headers):
        self.calls.append((url, dict(params or {}), dict(headers or {})))
        return self.handler(url, params or {}, headers or {})

    @property
    def urls(self):
        return [url for url, _, _ in self.calls if "/search" in url or url.endswith("/m")]


class GoogleClientTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_state()

    def tearDown(self) -> None:
        reset_state()

    def _scraper(self, fake, **kwargs):
        now = [1000.0]

        def clock():
            return now[0]

        def sleeper(delay):
            now[0] += delay

        return GoogleScraper(
            None,
            warmup=False,
            sleeper=sleeper,
            clock=clock,
            rng=random.Random(1),
            get=fake,
            **kwargs,
        )

    # -- parsing ---------------------------------------------------------
    def test_parse_results(self) -> None:
        findings = parse_results(RESULTS_PAGE, "Julia Evans", 10)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].url, "https://jvns.ca/")
        self.assertEqual(findings[0].source, "Google")
        self.assertIn("programming", (findings[0].detail or "").lower())

    def test_wrapper_and_google_links(self) -> None:
        self.assertEqual(google_url("/url?q=https://example.com/a&sa=U"), "https://example.com/a")
        self.assertIsNone(google_url("https://www.google.com/preferences"))
        self.assertIsNone(google_url("javascript:void(0)"))

    def test_wall_detection(self) -> None:
        self.assertTrue(is_wall(WALL_PAGE))
        self.assertFalse(is_wall(RESULTS_PAGE))

    # -- anti-block behaviour -------------------------------------------
    def test_block_triggers_cooldown_and_skips_next_query(self) -> None:
        fake = FakeGet(lambda url, params, headers: FakeResponse(WALL_PAGE))
        scraper = self._scraper(fake, cooldown=600)

        first = scraper.search("Julia Evans")
        self.assertEqual(first.status, BLOCKED)
        self.assertIn("cooling down", first.detail or "")
        self.assertGreater(cooldown_remaining(lambda: 1000.0), 0)

        calls_after_first = len(fake.calls)
        second = scraper.search("Linus Torvalds")
        self.assertEqual(second.status, BLOCKED)
        self.assertIn("cooling down", second.detail or "")
        self.assertEqual(len(fake.calls), calls_after_first, "no request during cooldown")

    def test_endpoint_fallback_finds_results(self) -> None:
        def handler(url, params, headers):
            if url.endswith("/m"):
                return FakeResponse(RESULTS_PAGE)
            return FakeResponse(WALL_PAGE)

        fake = FakeGet(handler)
        scraper = self._scraper(fake, cooldown=600)
        outcome = scraper.search("Julia Evans")
        self.assertEqual(outcome.status, FOUND)
        self.assertEqual(outcome.endpoint, "mobile")
        self.assertTrue(outcome.findings)
        self.assertEqual(cooldown_remaining(lambda: 1000.0), 0, "a success clears the block state")

    def test_http_429_is_treated_as_block(self) -> None:
        fake = FakeGet(lambda url, params, headers: FakeResponse("", status=429))
        outcome = self._scraper(fake, cooldown=60).search("someone")
        self.assertEqual(outcome.status, BLOCKED)
        self.assertIn("HTTP 429", outcome.detail or "")

    def test_query_budget_stops_requests(self) -> None:
        fake = FakeGet(lambda url, params, headers: FakeResponse(RESULTS_PAGE))
        scraper = self._scraper(fake, max_queries=1)
        self.assertTrue(scraper.search("Julia Evans").findings)
        before = len(fake.calls)
        outcome = scraper.search("Julia Evans again")
        self.assertEqual(outcome.status, INFO)
        self.assertIn("budget", outcome.detail or "")
        self.assertEqual(len(fake.calls), before)

    def test_requests_are_spaced_and_rotate_agents(self) -> None:
        delays: list[float] = []
        now = [1000.0]

        def sleeper(delay):
            delays.append(delay)
            now[0] += delay

        fake = FakeGet(lambda url, params, headers: FakeResponse(RESULTS_PAGE))
        scraper = GoogleScraper(
            None,
            warmup=False,
            min_interval=1.5,
            sleeper=sleeper,
            clock=lambda: now[0],
            rng=random.Random(2),
            get=fake,
        )
        scraper.search("Julia Evans")
        scraper.search("Julia Evans")
        self.assertTrue(any(delay >= 1.5 for delay in delays[1:]), delays)
        agents = {headers.get("User-Agent") for _, _, headers in fake.calls}
        self.assertGreaterEqual(len(agents), 2, "User-Agent must rotate between queries")

    def test_warmup_is_sent_once(self) -> None:
        fake = FakeGet(lambda url, params, headers: FakeResponse(RESULTS_PAGE))
        scraper = GoogleScraper(
            None,
            sleeper=lambda _: None,
            clock=lambda: 1000.0,
            rng=random.Random(3),
            get=fake,
        )
        scraper.search("Julia Evans")
        scraper.search("Julia Evans")
        warmups = [url for url, _, _ in fake.calls if url.endswith("/ncr")]
        self.assertEqual(len(warmups), 1)

    def test_crawl_never_fetches_search_engines(self) -> None:
        from specter.crawl import _crawlable

        self.assertFalse(_crawlable("https://www.google.com/search?q=x"))
        self.assertFalse(_crawlable("https://www.bing.com/search?q=x"))
        self.assertTrue(_crawlable("https://jvns.ca/about"))

    def test_block_message_names_the_way_out(self) -> None:
        fake = FakeGet(lambda url, params, headers: FakeResponse(WALL_PAGE))
        scraper = GoogleScraper(None, warmup=False, sleeper=lambda _: None, get=fake)
        outcome = scraper.search("Julia Evans")
        self.assertEqual(outcome.status, BLOCKED)
        self.assertIn("GOOGLE_API_KEY", outcome.detail or "")


if __name__ == "__main__":
    unittest.main()
