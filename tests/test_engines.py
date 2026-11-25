"""Offline tests for the Google engine, the lookup directory and the platform DB."""

import unittest

from specter.modules.search import (
    ALL_SOURCES,
    _google_url,
    _parse_google,
    dork_links,
)
from specter.modules.username import load_sites

GOOGLE_PAGE = """
<div class="g">
  <a href="/url?q=https://jvns.ca/&amp;sa=U&amp;ved=2ah"><h3>Julia Evans</h3></a>
  <div class="VwiC3b">A blog about programming, zines and debugging.</div>
</div>
<div class="g">
  <a href="https://www.google.com/preferences"><h3>Search settings</h3></a>
</div>
<div class="g">
  <a href="/url?q=https://jvns.ca/&amp;sa=U"><h3>Julia Evans again</h3></a>
</div>
"""


class GoogleEngineTests(unittest.TestCase):
    def test_static_results_are_parsed(self) -> None:
        findings = _parse_google(GOOGLE_PAGE, "Julia Evans", 10)
        self.assertEqual(len(findings), 1, "duplicates and Google-owned links are dropped")
        finding = findings[0]
        self.assertEqual(finding.source, "Google")
        self.assertEqual(finding.url, "https://jvns.ca/")
        self.assertEqual(finding.title, "Julia Evans")
        self.assertIn("blog", (finding.detail or "").lower())

    def test_result_limit_is_respected(self) -> None:
        page = GOOGLE_PAGE + """
        <div class="g"><a href="/url?q=https://example.org/julia-evans"><h3>Julia Evans profile</h3></a></div>
        """
        self.assertEqual(len(_parse_google(page, "Julia Evans", 1)), 1)

    def test_wrapper_decoding(self) -> None:
        self.assertEqual(
            _google_url("/url?q=https://example.com/a%3Fb%3D1&sa=U"), "https://example.com/a?b=1"
        )
        self.assertIsNone(_google_url("https://www.google.com/preferences"))
        self.assertIsNone(_google_url("javascript:void(0)"))

    def test_irrelevant_results_are_discarded(self) -> None:
        page = '<div class="g"><a href="https://beautyjulia.com/fr"><h3>Parfumerie</h3></a></div>'
        self.assertEqual(_parse_google(page, "Linus Torvalds", 5), [])


class LookupDirectoryTests(unittest.TestCase):
    def test_lookups_are_added_per_kind(self) -> None:
        username = dict(dork_links("jdoe", "username"))
        self.assertIn("Zeal", username)
        self.assertIn("Bing", username)
        email = dict(dork_links("jane@example.com", "email"))
        self.assertIn("Epieos", email)
        domain = dict(dork_links("example.com", "domain"))
        self.assertIn("crt.sh", domain)

    def test_no_duplicate_names(self) -> None:
        for kind in ("name", "email", "username", "phone", "domain", "ip"):
            names = [name for name, _ in dork_links("target", kind)]
            self.assertEqual(len(names), len(set(names)), kind)

    def test_templates_are_rendered(self) -> None:
        for kind in ("name", "email", "username", "phone", "domain", "ip"):
            for name, url in dork_links("jane doe+1", kind):
                self.assertTrue(url.startswith("http"), f"{kind}/{name}")
                self.assertNotIn("{", url, f"{kind}/{name}")


class PlatformDatabaseTests(unittest.TestCase):
    def test_expanded_database(self) -> None:
        sites = {site["name"]: site for site in load_sites()}
        self.assertGreaterEqual(len(sites), 75)
        for name in ("guns.lol", "Linktree", "About.me", "Gravatar"):
            self.assertIn(name, sites)

    def test_guns_lol_uses_absent_marker(self) -> None:
        sites = {site["name"]: site for site in load_sites()}
        site = sites["guns.lol"]
        self.assertEqual(site["check"], "status")
        self.assertEqual(site["absent"], "username not found")

    def test_status_sites_are_well_formed(self) -> None:
        for site in load_sites():
            if site["check"] == "status":
                self.assertIn("{u}", site["url"])
                self.assertIsInstance(site.get("expect", [200]), list)

    def test_crawl_source_is_registered(self) -> None:
        self.assertIn("crawl", ALL_SOURCES)


if __name__ == "__main__":
    unittest.main()
