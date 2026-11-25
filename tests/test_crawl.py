"""Offline tests for the smart crawler: scoring, extraction, budget and pruning."""

import unittest

from specter.crawl import (
    FetchResult,
    SmartCrawler,
    Target,
    extract_page,
    url_key,
)
from specter.modules.scrape import crawl_findings
from specter.person import PersonInput


SEED = "https://jane.example/"
CONTACT = "https://jane.example/contact"
GALLERY = "https://jane.example/gallery"
PROFILE = "https://github.com/jdoe"

SEED_HTML = """
<html><head><title>Jane Doe — studio</title><meta name="description" content="Design studio"></head>
<body>
  <a href="/contact">Contact Jane Doe</a>
  <a href="/about">About Jane Doe</a>
  <a href="/gallery">Photo gallery</a>
  <a href="https://github.com/jdoe">GitHub</a>
</body></html>
"""

CONTACT_HTML = """
<html><head><title>Contact Jane Doe</title></head>
<body>
  <h1>Contact</h1>
  <p>Email jane.doe@example.com or call +33 6 12 34 56 78.</p>
  <a href="mailto:hello@jane.example">Write to us</a>
  <a href="https://www.linkedin.com/in/janedoe">LinkedIn</a>
  <script type="application/ld+json">
  {"@context":"https://schema.org","@type":"Person","name":"Jane Doe",
   "jobTitle":"Designer","worksFor":{"@type":"Organization","name":"Acme Studio"},
   "email":"jane@acme.example","telephone":"+33612345678",
   "sameAs":["https://github.com/jdoe"]}
  </script>
</body></html>
"""

GALLERY_HTML = "<html><head><title>Photos of the studio</title></head><body><p>Nothing here.</p></body></html>"


class SmartCrawlTests(unittest.TestCase):
    def _fake(self, pages, requested=None):
        def fetch(url):
            if requested is not None:
                requested.append(url)
            html = pages.get(url)
            if html is None:
                return FetchResult(ok=False, url=url, status=404, error="HTTP 404")
            return FetchResult(ok=True, url=url, status=200, text=html, content_type="text/html")

        return fetch

    def test_url_key_ignores_noise(self):
        self.assertEqual(
            url_key("https://www.Example.com/a/?utm_source=news#top"),
            "example.com/a",
        )
        self.assertEqual(url_key("http://example.com/a"), url_key("https://example.com/a/"))

    def test_extract_page_pulls_identity(self):
        page = extract_page(CONTACT_HTML, CONTACT, region="FR")
        self.assertEqual(page.title, "Contact Jane Doe")
        self.assertIn("jane.doe@example.com", page.emails)
        self.assertIn("hello@jane.example", page.emails)
        self.assertIn("jane@acme.example", page.emails)
        self.assertIn("+33612345678", page.phones)
        self.assertIn("Jane Doe", page.names)
        self.assertIn("Acme Studio", page.organisations)
        self.assertIn("GitHub", page.profiles)
        self.assertIn(PROFILE, page.profiles["GitHub"])
        self.assertIn("LinkedIn", page.profiles)

    def test_crawl_follows_relevant_links_only(self):
        requested = []
        pages = {SEED: SEED_HTML, CONTACT: CONTACT_HTML, GALLERY: GALLERY_HTML}
        crawler = SmartCrawler(
            None,
            budget=2,
            max_depth=2,
            respect_robots=False,
            delay_per_host=0,
            fetcher=self._fake(pages, requested),
        )
        result = crawler.run([(SEED, "")], Target.from_query("Jane Doe"))
        self.assertEqual([page.url for page in result.pages], [SEED, CONTACT])
        self.assertNotIn(GALLERY, requested)
        self.assertNotIn("https://jane.example/about", requested)
        self.assertGreater(result.pruned, 0)
        self.assertEqual(result.stopped, "page budget reached")

    def test_budget_and_duplicates(self):
        copy = "https://jane.example/about"
        pages = {
            SEED: SEED_HTML,
            CONTACT: "<html><body><p>Jane Doe jane@example.com</p></body></html>",
            copy: "<html><body><p>Jane Doe jane@example.com</p></body></html>",
        }
        crawler = SmartCrawler(
            None,
            budget=4,
            max_depth=1,
            respect_robots=False,
            delay_per_host=0,
            fetcher=self._fake(pages),
        )
        result = crawler.run([(SEED, "")], Target.from_query("Jane Doe"))
        self.assertLessEqual(result.fetched, 4)
        self.assertEqual(result.duplicates, 1)
        self.assertEqual(len(result.pages), 2)

    def test_crawl_findings_shape(self):
        pages = {SEED: SEED_HTML, CONTACT: CONTACT_HTML}
        findings = crawl_findings(
            "",
            [(SEED, "")],
            None,
            None,
            person=PersonInput(first_name="Jane", last_name="Doe", usernames=["jdoe"]),
            budget=3,
            depth=2,
            respect_robots=False,
            fetcher=self._fake(pages),
        )
        self.assertEqual(findings[0].source, "Crawl")
        self.assertEqual(findings[0].status, "info")
        self.assertIn("pages analysed", findings[0].data)
        sources = [finding.source for finding in findings]
        self.assertIn("Crawled pages · contacts", sources)
        self.assertTrue(any(source.startswith("Scraped ·") for source in sources))
        contacts = next(f for f in findings if f.source == "Crawled pages · contacts")
        self.assertIn("jane.doe@example.com", contacts.data["email addresses"])

    def test_target_from_person_weights_handles(self):
        target = Target.from_person(PersonInput(name="Jane Doe", usernames=["jdoe"], domains=["jane.dev"]))
        self.assertIn("jdoe", target.terms)
        self.assertIn("jane.dev", target.terms)
        self.assertGreaterEqual(target.score_text("portfolio of jdoe"), 2.0)

    def test_empty_target_is_reported_not_crawled(self):
        findings = crawl_findings("", [(SEED, "")], None, None, terms=[])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "info")


if __name__ == "__main__":
    unittest.main()
