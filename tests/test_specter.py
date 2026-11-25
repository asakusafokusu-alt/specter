"""Offline tests for SPECTER (no network access required)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from specter import gui
from specter.cli import build_parser
from specter.config import Config
from specter.correlate import Evidence, assess, host_of, location_match, name_similarity
from specter.person import (
    PersonInput,
    assessment_findings,
    derived_usernames,
    normalize_person,
    split_values,
)
from specter.images import extract_meta
from specter.investigate import detect_target
from specter.models import FOUND, INFO, MANUAL, Report, Finding, ImageRef
from specter.modules.breaches import _xon_findings
from specter.modules.domain import _rdap_parse, normalize_domain
from specter.modules.email import split_email, validate_email
from specter.modules.ip import investigate_ip
from specter.modules.phone import investigate_phone
from specter.modules.search import (
    ALL_SOURCES,
    _bing_url,
    _merge_web,
    _parse_bing,
    _parse_duckduckgo,
    _url_key,
    dork_links,
    dork_queries,
)
from specter.modules.username import USERNAME_RE, load_sites, validate_username
from specter.regions import (
    AUTO_LABEL,
    choices as region_choices,
    dial_code,
    label_for,
    region_from_label,
)
from specter.report import render_html, render_markdown, write_report


class UsernameTests(unittest.TestCase):
    def test_validation(self) -> None:
        self.assertEqual(validate_username("@torvalds"), "torvalds")
        self.assertEqual(validate_username("a_b-c.d"), "a_b-c.d")
        for bad in ("", "two words", "-leading", "x" * 40, "bad/slash"):
            with self.assertRaises(ValueError):
                validate_username(bad)

    def test_site_database(self) -> None:
        sites = load_sites()
        self.assertGreaterEqual(len(sites), 40)
        names = [site["name"] for site in sites]
        self.assertEqual(len(names), len(set(names)), "platform names must be unique")
        allowed = {"json", "post_json", "status", "marker", "title", "steam", "manual"}
        for site in sites:
            self.assertIn("name", site)
            self.assertIn("category", site)
            self.assertIn("url", site)
            self.assertIn("{u}", site["url"])
            self.assertIn(site["check"], allowed, site["name"])
            if site["check"] in ("json", "post_json"):
                self.assertIn("request", site, site["name"])
                self.assertTrue(site.get("json_any") or site.get("json_equals"), site["name"])
        automated = [site for site in sites if site["check"] != "manual"]
        self.assertGreaterEqual(len(automated), 25)


class EmailTests(unittest.TestCase):
    def test_valid_addresses(self) -> None:
        for value in ("a@b.co", "first.last+tag@example.com", "UPPER@Example.COM"):
            self.assertTrue(validate_email(value))
        self.assertEqual(validate_email("A@B.CO"), "a@b.co")

    def test_invalid_addresses(self) -> None:
        for value in ("plain", "a@b", "a..b@c.com", "@example.com", "x@y..com"):
            with self.assertRaises(ValueError):
                validate_email(value)

    def test_split(self) -> None:
        self.assertEqual(split_email("user@example.com"), ("user", "example.com"))


class TargetDetectionTests(unittest.TestCase):
    def test_detection(self) -> None:
        self.assertEqual(detect_target("someone@example.com"), "email")
        self.assertEqual(detect_target("8.8.8.8"), "ip")
        self.assertEqual(detect_target("2001:4860:4860::8888"), "ip")
        self.assertEqual(detect_target("example.com"), "domain")
        self.assertEqual(detect_target("+14155552671"), "phone")
        self.assertEqual(detect_target("415-555-2671"), "phone")
        self.assertEqual(detect_target("Jane Doe"), "name")
        self.assertEqual(detect_target("torvalds"), "username")

    def test_domain_normalization(self) -> None:
        self.assertEqual(normalize_domain("https://WWW.Example.com/path"), "www.example.com")
        with self.assertRaises(ValueError):
            normalize_domain("not a domain")
        with self.assertRaises(ValueError):
            normalize_domain("example.123")


class SearchTests(unittest.TestCase):
    def test_dorks(self) -> None:
        queries = dork_queries("Jane Doe", "name")
        self.assertTrue(any('"Jane Doe"' == query for query in queries))
        self.assertIn("web", ALL_SOURCES)
        self.assertTrue(dork_queries("example.com", "domain"))
        links = dork_links("Jane Doe", "name")
        engines = [name for name, _ in links]
        self.assertIn("Google", engines)
        self.assertIn("Bing", engines)
        self.assertGreaterEqual(len(links), 7)
        self.assertTrue(all(url.startswith("https://") for _, url in links))

    def test_phone(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Config(Path(tmp) / "config.json")
            findings = investigate_phone("+14155552671", None, config)  # type: ignore[arg-type]
        data = findings[0].data
        self.assertEqual(data["E.164"], "+14155552671")
        self.assertIn("type", data)
        self.assertTrue(any(finding.status == MANUAL for finding in findings))

    def test_private_ip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Config(Path(tmp) / "config.json")
            findings = investigate_ip("127.0.0.1", None, config)  # type: ignore[arg-type]
        self.assertTrue(findings)
        self.assertIn("private", findings[0].detail.lower())


class KeylessSourceTests(unittest.TestCase):
    def test_bing_redirect_decode(self) -> None:
        import base64

        target = "https://en.wikipedia.org/wiki/Linus_Torvalds"
        payload = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
        href = f"https://www.bing.com/ck/a?!&&p=abc&u=a1{payload}&ntb=1"
        self.assertEqual(_bing_url(href), target)
        self.assertEqual(_bing_url("https://example.com/x"), "https://example.com/x")
        self.assertIsNone(_bing_url("/relative/path"))

    def test_bing_html_parse(self) -> None:
        import base64

        target = "https://en.wikipedia.org/wiki/Jane_Doe"
        encoded = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
        text = (
            '<li class="b_algo"><h2><a href="https://www.bing.com/ck/a?u=a1%s">'
            "Jane Doe - Wikipedia</a></h2><p>Jane Doe is a researcher.</p></li>"
            '<li class="b_algo"><h2><a href="https://unrelated.example/x">'
            "Unrelated page</a></h2><p>Nothing to do with the query.</p></li>" % encoded
        )
        findings = _parse_bing(text, '"Jane Doe"', 5)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].url, target)
        self.assertEqual(findings[0].source, "Bing")
        self.assertIn("researcher", findings[0].detail or "")

    def test_duckduckgo_html_parse(self) -> None:
        text = (
            '<div class="result results_links result--ad">'
            '<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com'
            '%2Fjane&amp;rut=1">Jane Doe profile</a>'
            '<a class="result__snippet" href="x">Jane Doe writes about OSINT.</a></div>'
            "</body>"
        )
        findings = _parse_duckduckgo(text, '"Jane Doe"', 5)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].url, "https://example.com/jane")
        self.assertEqual(findings[0].source, "DuckDuckGo")

    def test_cross_engine_merge(self) -> None:
        first = Finding(
            source="Bing",
            category="Web",
            status=FOUND,
            title="Short",
            url="https://Example.com/page/?utm_source=x",
            detail="short",
        )
        second = Finding(
            source="DuckDuckGo",
            category="Web",
            status=FOUND,
            title="Longer title",
            url="https://example.com/page",
            detail="a much longer snippet from the other engine",
        )
        merged = _merge_web([[first], [second]], 5)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].confidence, "high")
        self.assertEqual(merged[0].data["also reported by"], ["Bing", "DuckDuckGo"])
        self.assertIn("longer snippet", merged[0].detail or "")
        self.assertEqual(_url_key("https://www.example.com/a/"), "example.com/a")

    def test_keyless_breach_parsing(self) -> None:
        payload = {
            "BreachesSummary": {"site": "Alpha;Beta"},
            "ExposedBreaches": {
                "breaches_details": [
                    {
                        "breach": "Alpha",
                        "domain": "alpha.example",
                        "industry": "Retail",
                        "xposed_data": "Email addresses;Passwords",
                        "xposed_records": 1000,
                        "xposed_date": "2021",
                        "logo": "https://xposedornot.com/static/logos/Alpha.png",
                    }
                ]
            },
            "BreachMetrics": {
                "risk": [{"risk_label": "High", "risk_score": 75}],
                "xposed_data": [
                    {"name": "x", "value": 2, "children": [{"name": "data_Passwords", "value": 1}]}
                ],
                "yearwise_details": [{"y2020": 1, "y2021": 2}],
            },
            "PastesSummary": {"cnt": 1},
        }
        findings = _xon_findings("jane@example.com", payload)
        self.assertGreaterEqual(len(findings), 3)
        summary = findings[0]
        self.assertEqual(summary.data["breaches"], 2)
        self.assertEqual(summary.data["risk"], "High")
        self.assertEqual(summary.data["breach names"], ["Alpha", "Beta"])
        detail = next(item for item in findings if item.title == "Alpha")
        self.assertEqual(detail.data["data classes"], ["Email addresses", "Passwords"])
        self.assertEqual(detail.images[0].url, "https://xposedornot.com/static/logos/Alpha.png")

    def test_rdap_parsing(self) -> None:
        payload = {
            "ldhName": "EXAMPLE.COM",
            "status": ["client transfer prohibited"],
            "events": [
                {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2030-08-13T04:00:00Z"},
            ],
            "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}],
            "secureDNS": {"delegationSigned": True},
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                              ["fn", {}, "text", "Example Registrar"]]],
                    "entities": [
                        {
                            "roles": ["abuse"],
                            "vcardArray": ["vcard", [["email", {}, "text", "abuse@example.net"]]],
                        }
                    ],
                }
            ],
        }
        data = _rdap_parse(payload, "https://rdap.example/v1/domain/example.com")
        self.assertEqual(data["registrar"], "Example Registrar")
        self.assertEqual(data["created"], "1995-08-14")
        self.assertEqual(data["expires"], "2030-08-13")
        self.assertEqual(data["name servers"], ["a.iana-servers.net"])
        self.assertEqual(data["abuse contact"], "abuse@example.net")
        self.assertTrue(data["DNSSEC"])


class ImageTests(unittest.TestCase):
    def test_meta_extraction(self) -> None:
        page = (
            '<html><head><title>Jane Doe</title>'
            '<meta property="og:image" content="/avatar.png">'
            '<meta name="description" content="Researcher">'
            '<link rel="icon" href="/favicon.ico"></head></html>'
        )
        meta = extract_meta(page, "https://example.com/jane")
        self.assertEqual(meta["image"], "https://example.com/avatar.png")
        self.assertEqual(meta["favicon"], "https://example.com/favicon.ico")
        self.assertEqual(meta["description"], "Researcher")
        self.assertEqual(meta["title"], "Jane Doe")

    def test_images_count_and_ordering(self) -> None:
        report = Report(target="jane", target_type="username")
        report.add(
            Finding(
                source="Example",
                category="Profile",
                status=FOUND,
                title="Jane",
                url="https://example.com/jane",
                images=[ImageRef(url="https://example.com/a.png", kind="profile")],
            )
        )
        payload = report.finish().to_dict()
        self.assertEqual(payload["counts"]["images"], 1)
        keys = list(payload["findings"][0].keys())
        self.assertLess(keys.index("title"), keys.index("source"))
        self.assertEqual(payload["findings"][0]["images"][0]["kind"], "profile")


class PersonProfileTests(unittest.TestCase):
    def _person(self) -> PersonInput:
        return PersonInput(
            name="Jane Doe",
            emails=["jane@example.com"],
            usernames=["jdoe"],
            domains=["jane.dev"],
            location="Lyon, France",
        )

    def _profile(self) -> Finding:
        return Finding(
            source="GitHub profile",
            category="GitHub",
            status=FOUND,
            title="Jane Doe",
            url="https://github.com/jdoe",
            data={
                "name": "Jane Doe",
                "location": "Lyon, France",
                "website": "https://jane.dev",
                "public email": "jane@example.com",
            },
        )

    def _gravatar(self) -> Finding:
        return Finding(
            source="Gravatar",
            category="Email",
            status=FOUND,
            title="Jane Doe",
            url="https://gravatar.com/jane",
            data={"display name": "Jane Doe", "location": "Lyon"},
        )

    def test_matching_helpers(self) -> None:
        self.assertGreaterEqual(name_similarity("Jane Doe", "Jane A. Doe"), 0.99)
        self.assertLess(name_similarity("Jane Doe", "John Doe"), 0.6)
        self.assertTrue(location_match("Lyon, France", "Lyon"))
        self.assertFalse(location_match("Lyon", "Berlin"))
        self.assertEqual(host_of("https://www.jane.dev/about"), "jane.dev")

    def test_single_source_is_discounted(self) -> None:
        person = self._person()
        profile = self._profile()
        single = assess(
            person,
            [Evidence(label="Username · jdoe", kind="username", value="jdoe", findings=[profile])],
        )
        both = assess(
            person,
            [
                Evidence(label="Username · jdoe", kind="username", value="jdoe", findings=[profile]),
                Evidence(
                    label="Email · jane@example.com",
                    kind="email",
                    value="jane@example.com",
                    findings=[self._gravatar()],
                ),
            ],
        )
        self.assertIn(single.band, ("moderate", "weak"))
        self.assertEqual(both.band, "strong")
        self.assertGreater(both.score, single.score)
        self.assertTrue(any(link.right == "jane@example.com" for link in single.links))
        self.assertEqual(len(both.links), len({(l.left, l.right, l.basis) for l in both.links}))

    def test_contradicting_names(self) -> None:
        other = Finding(
            source="Gravatar",
            category="Email",
            status=FOUND,
            title="Marc Smith",
            data={"display name": "Marc Smith"},
        )
        assessment = assess(
            PersonInput(name="Jane Doe", usernames=["jdoe"]),
            [
                Evidence(label="Username · jdoe", kind="username", value="jdoe", findings=[self._profile()]),
                Evidence(label="Email · jane@example.com", kind="email", value="jane@example.com", findings=[other]),
            ],
        )
        self.assertTrue(assessment.conflicts)
        self.assertIn("Marc Smith", assessment.conflicts[0])

    def test_input_normalization(self) -> None:
        cleaned, notes = normalize_person(
            PersonInput(
                name="  Jane   Doe ",
                emails=["JANE@Example.com", "not-an-address"],
                usernames=["-bad-"],
                domains=["https://Example.com/path"],
                ips=["8.8.8.8", "999.1.1.1"],
            )
        )
        self.assertEqual(cleaned.full_name, "Jane Doe")
        self.assertEqual(cleaned.emails, ["jane@example.com"])
        self.assertEqual(cleaned.domains, ["example.com"])
        self.assertEqual(cleaned.ips, ["8.8.8.8"])
        self.assertEqual(cleaned.usernames, [])
        self.assertTrue(notes)
        derived = derived_usernames(PersonInput(emails=["jane.doe+news@example.com"]))
        self.assertIn("janedoe", derived)
        self.assertIn("jane.doe", derived)
        self.assertLessEqual(len(derived), 2)

    def test_split_values(self) -> None:
        self.assertEqual(split_values("a@x.com, b@y.com"), ["a@x.com", "b@y.com"])
        self.assertEqual(split_values(["a@x.com", "a@x.com"]), ["a@x.com"])

    def test_assessment_findings(self) -> None:
        person = self._person()
        assessment = assess(
            person,
            [Evidence(label="Username · jdoe", kind="username", value="jdoe", findings=[self._profile()])],
        )
        findings = assessment_findings(assessment, person)
        summary = findings[0]
        self.assertEqual(summary.category, "Assessment")
        self.assertIn(assessment.band, summary.title.lower())
        self.assertEqual(summary.data["band"], assessment.band)
        self.assertTrue(any(finding.source == "Identity links" for finding in findings))
        links = next(finding for finding in findings if finding.source == "Identity links")
        self.assertTrue(links.data["links"])
        self.assertIn("from", links.data["links"][0])

    def test_person_parser(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "person",
                "--first",
                "Jane",
                "--last",
                "Doe",
                "--email",
                "a@b.co",
                "--email",
                "c@d.co",
                "--username",
                "jdoe",
                "--location",
                "Lyon",
            ]
        )
        self.assertEqual(args.command, "person")
        self.assertEqual(args.email, ["a@b.co", "c@d.co"])
        self.assertEqual(args.first, "Jane")
        person = PersonInput(
            first_name=args.first,
            last_name=args.last,
            emails=split_values(args.email),
            usernames=split_values(args.username),
            location=args.location,
        )
        self.assertEqual(person.full_name, "Jane Doe")
        self.assertEqual(person.emails, ["a@b.co", "c@d.co"])

    def test_report_exports_identity(self) -> None:
        report = Report(target="jane", target_type="person profile")
        report.identity = {
            "band": "moderate",
            "score": 50,
            "verdict": "Probable match for Jane Doe.",
            "links": [{"from": "a", "to": "b", "basis": "c", "weight": 20}],
            "conflicts": ["Two names differ"],
            "gaps": ["Add an email"],
        }
        payload = report.finish().to_dict()
        self.assertEqual(payload["identity"]["score"], 50)
        markdown = render_markdown(report)
        self.assertIn("## Identity assessment", markdown)
        self.assertIn("Probable match for Jane Doe.", markdown)
        html = render_html(report, embed_images=False)
        self.assertIn("Identity assessment", html)
        self.assertIn("Probable match for Jane Doe.", html)


class GuiTests(unittest.TestCase):
    def test_region_picker(self) -> None:
        choices = region_choices()
        self.assertGreaterEqual(len(choices), 200)
        labels = [label for label, _ in choices]
        self.assertIn("France (+33)", labels)
        self.assertEqual(region_from_label("France (+33)"), "FR")
        self.assertIsNone(region_from_label(AUTO_LABEL))
        self.assertEqual(label_for("FR"), "France (+33)")
        self.assertEqual(label_for("ZZ"), AUTO_LABEL)
        self.assertEqual(dial_code("FR"), "+33")

    def test_finding_text_is_content_first(self) -> None:
        finding = Finding(
            source="Example",
            category="Profile",
            status=FOUND,
            title="Jane Doe",
            detail="A public profile",
            url="https://example.com/jane",
            data={
                "location": "Paris",
                "accounts": [{"site": "Example", "url": "https://example.com/j"}],
                "verified": True,
            },
            images=[ImageRef(url="https://example.com/a.png", kind="profile")],
            confidence="medium",
        )
        text = gui.finding_text(finding)
        self.assertLess(text.index("A public profile"), text.index("via Example"))
        self.assertIn("location: Paris", text)
        self.assertIn("site: Example", text)
        self.assertIn("verified: yes", text)
        self.assertIn("https://example.com/a.png", text)
        self.assertIn("medium confidence", text)

    def test_report_summary(self) -> None:
        report = Report(target="jane", target_type="username")
        report.add(Finding(source="Example", category="Profile", status=FOUND))
        report.finish()
        summary = gui.report_summary(report)
        self.assertIn("1 found", summary)
        self.assertIn("image(s)", summary)

    def test_window_builds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                app = gui.SpecterApp(Config(Path(tmp) / "config.json"))
            except Exception as exc:  # noqa: BLE001 - headless runners have no display
                if "display" in str(exc).lower() or "tcl" in str(exc).lower():
                    self.skipTest("no display available")
                raise
            try:
                app.root.update_idletasks()
                self.assertIn("SPECTER", app.root.title())
                self.assertIn("France (+33)", app.region_values)
                self.assertTrue(app.source_vars["web"].get())
            finally:
                app.destroy()


class ReportTests(unittest.TestCase):
    def _report(self, target: str = "Jane Doe") -> Report:
        report = Report(target=target, target_type="person name")
        report.add(
            Finding(
                source="Example",
                category="Web",
                status=FOUND,
                title="Profile",
                url="https://example.com/profile",
                detail="A <script>alert(1)</script> snippet",
                data={"location": "Paris", "accounts": [1, 2]},
            )
        )
        report.add(
            Finding(
                source="Manual",
                category="Web",
                status=MANUAL,
                url="https://example.com/manual",
                detail="Open manually",
            )
        )
        report.notes.append("Test note")
        return report.finish()

    def test_json_roundtrip(self) -> None:
        report = self._report()
        payload = report.to_dict()
        encoded = json.dumps(payload)
        self.assertIn("Jane Doe", encoded)
        self.assertEqual(payload["counts"]["found"], 1)
        self.assertEqual(payload["counts"]["manual"], 1)

    def test_html_escapes_user_data(self) -> None:
        html = render_html(self._report("<script>alert(1)</script>"))
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_markdown(self) -> None:
        markdown = render_markdown(self._report())
        self.assertIn("# SPECTER report", markdown)
        self.assertIn("## Manual verification links", markdown)

    def test_write_all_formats(self) -> None:
        report = self._report()
        with tempfile.TemporaryDirectory() as tmp:
            written = write_report(report, Path(tmp) / "report", "all")
            self.assertEqual(len(written), 3)
            for path in written:
                self.assertTrue(path.exists())
                self.assertGreater(path.stat().st_size, 100)


if __name__ == "__main__":
    unittest.main()
