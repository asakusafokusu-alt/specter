"""Email intelligence: validation, domain posture, linked accounts and breaches."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .. import dns_util, images
from ..config import Config
from ..http import HttpClient
from ..models import BLOCKED, ERROR, FOUND, INFO, NOT_FOUND, Finding, ImageRef
from .breaches import check_breaches

EMAIL_RE = re.compile(
    r"^(?=.{3,254}$)[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)

PROVIDERS = {
    "gmail.com": "Gmail (Google)",
    "googlemail.com": "Gmail (Google)",
    "outlook.com": "Outlook (Microsoft)",
    "hotmail.com": "Outlook (Microsoft)",
    "live.com": "Outlook (Microsoft)",
    "msn.com": "Outlook (Microsoft)",
    "yahoo.com": "Yahoo",
    "yahoo.fr": "Yahoo",
    "ymail.com": "Yahoo",
    "icloud.com": "iCloud (Apple)",
    "me.com": "iCloud (Apple)",
    "mac.com": "iCloud (Apple)",
    "proton.me": "Proton Mail",
    "protonmail.com": "Proton Mail",
    "pm.me": "Proton Mail",
    "tutanota.com": "Tutanota",
    "tuta.com": "Tutanota",
    "gmx.com": "GMX",
    "gmx.de": "GMX",
    "gmx.net": "GMX",
    "mail.com": "Mail.com",
    "yandex.com": "Yandex",
    "yandex.ru": "Yandex",
    "zoho.com": "Zoho",
    "fastmail.com": "Fastmail",
    "hey.com": "HEY",
    "aol.com": "AOL",
    "qq.com": "QQ Mail (Tencent)",
    "163.com": "NetEase Mail",
    "126.com": "NetEase Mail",
    "mail.ru": "Mail.ru",
    "inbox.ru": "Mail.ru",
    "list.ru": "Mail.ru",
    "rambler.ru": "Rambler",
    "posteo.de": "Posteo",
    "disroot.org": "Disroot",
    "riseup.net": "Riseup",
    "hushmail.com": "Hushmail",
    "web.de": "Web.de",
    "orange.fr": "Orange",
    "laposte.net": "La Poste",
    "free.fr": "Free",
    "sfr.fr": "SFR",
    "wanadoo.fr": "Orange",
    "comcast.net": "Comcast",
    "verizon.net": "Verizon",
    "att.net": "AT&T",
}

ROLE_ACCOUNTS = {
    "admin", "administrator", "billing", "contact", "hello", "help", "hr",
    "info", "inquiries", "jobs", "legal", "mail", "marketing", "media",
    "noreply", "no-reply", "office", "postmaster", "press", "privacy",
    "sales", "security", "service", "support", "team", "webmaster", "abuse",
}

TYPO_DOMAINS = {
    "gmial.com": "gmail.com",
    "gmai.com": "gmail.com",
    "gmil.com": "gmail.com",
    "gmail.co": "gmail.com",
    "gnail.com": "gmail.com",
    "hotmial.com": "hotmail.com",
    "hotmai.com": "hotmail.com",
    "outlok.com": "outlook.com",
    "outllok.com": "outlook.com",
    "yahooo.com": "yahoo.com",
    "yaho.com": "yahoo.com",
    "iclould.com": "icloud.com",
    "icoud.com": "icloud.com",
    "protonmial.com": "protonmail.com",
}


def _disposable_domains() -> set[str]:
    from pathlib import Path

    path = Path(__file__).resolve().parent.parent / "data" / "disposable_domains.txt"
    try:
        return {
            line.strip().lower()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        }
    except OSError:
        return set()


def validate_email(value: str) -> str:
    email = value.strip().strip("<>").lower()
    if not EMAIL_RE.match(email):
        raise ValueError("That does not look like a valid email address.")
    if ".." in email:
        raise ValueError("Email local part cannot contain consecutive dots.")
    return email


def split_email(email: str) -> tuple[str, str]:
    local, _, domain = email.partition("@")
    return local, domain


def investigate_email(
    email: str,
    http: HttpClient,
    config: Config,
    *,
    include_breaches: bool = True,
    include_probes: bool = True,
) -> list[Finding]:
    email = validate_email(email)
    local, domain = split_email(email)
    findings: list[Finding] = []
    provider = PROVIDERS.get(domain)
    disposable = domain in _disposable_domains()
    typo = TYPO_DOMAINS.get(domain)
    role = local.split("+")[0] in ROLE_ACCOUNTS

    findings.append(
        Finding(
            source="Validation",
            category="Email",
            status=FOUND,
            title=email,
            detail="Syntax is valid.",
            data={
                "local part": local,
                "domain": domain,
                "provider": provider or "unknown / custom domain",
                "account type": "role address" if role else "personal-looking address",
                "disposable domain": "yes" if disposable else "no",
                **({"did you mean": f"{local}@{typo}"} if typo else {}),
            },
        )
    )

    if disposable:
        findings.append(
            Finding(
                source="Disposable check",
                category="Email",
                status=INFO,
                title="Disposable email domain",
                detail="The domain is on the known disposable-email list; treat it as low-trust.",
            )
        )

    # ---- DNS / domain posture -----------------------------------------
    mx = dns_util.resolve(domain, "MX")
    a_record = dns_util.resolve(domain, "A")
    spf = dns_util.spf(domain)
    dmarc = dns_util.dmarc(domain)
    null_mx = any(record.strip() in ("0 .", ".") or record.strip().endswith(" .") for record in mx.records)
    usable_mx = [
        record
        for record in mx.records
        if record.strip() not in ("0 .", ".") and not record.strip().endswith(" .")
    ]
    posture: dict[str, Any] = {
        "MX": ", ".join(usable_mx[:6]) if usable_mx else ("null MX (no mail accepted)" if null_mx else "none"),
        "SPF": spf or "not published",
        "DMARC": dmarc or "not published",
    }
    if a_record.records:
        posture["A"] = ", ".join(a_record.records[:4])
    if usable_mx:
        mail_detail = "Domain publishes mail exchangers."
    elif null_mx:
        mail_detail = "Null MX record: the domain explicitly does not accept email."
    else:
        mail_detail = mx.error or "No MX records: this domain cannot receive email."
    findings.append(
        Finding(
            source="Mail domain",
            category="Email",
            status=FOUND if usable_mx else INFO,
            title=domain,
            detail=mail_detail,
            data=posture,
        )
    )

    # ---- Gravatar -------------------------------------------------------
    digest = hashlib.md5(email.encode("utf-8")).hexdigest()  # noqa: S324 - Gravatar's public hash
    gravatar = http.get(f"https://gravatar.com/{digest}.json")
    if gravatar.status == 200:
        payload = gravatar.json() or {}
        entry = (payload.get("entry") or [{}])[0]
        accounts = [
            {
                "site": account.get("shortname") or account.get("domain"),
                "url": account.get("url"),
                "username": account.get("username"),
                "verified": account.get("verified"),
                "name": account.get("display"),
            }
            for account in entry.get("accounts", [])
        ]
        name_parts = entry.get("name") or {}
        full_name = " ".join(
            part
            for part in (name_parts.get("givenName"), name_parts.get("familyName"))
            if part
        )
        photos = [
            photo.get("value")
            for photo in entry.get("photos", [])
            if photo.get("value")
        ]
        thumbnail = entry.get("thumbnailUrl") or (photos[0] if photos else None)
        image = None
        if thumbnail:
            absolute = images.absolute_image_url(thumbnail, "https://gravatar.com")
            if absolute:
                image = ImageRef(
                    url=absolute,
                    alt=entry.get("displayName") or full_name or email,
                    kind="profile",
                    page_url=entry.get("profileUrl"),
                )
        data = {
            "display name": entry.get("displayName"),
            "name": full_name or None,
            "about": entry.get("aboutMe"),
            "location": entry.get("currentLocation"),
            "profile": entry.get("profileUrl"),
            "preferred username": entry.get("preferredUsername"),
            "urls": entry.get("urls"),
            "accounts": accounts,
            "photos": photos,
        }
        findings.append(
            Finding(
                source="Gravatar",
                category="Email",
                status=FOUND,
                title=entry.get("displayName") or full_name or "Gravatar profile",
                detail=(
                    entry.get("aboutMe")
                    or f"{len(accounts)} linked account(s) disclosed by Gravatar."
                ),
                url=entry.get("profileUrl") or f"https://gravatar.com/{digest}",
                data={key: value for key, value in data.items() if value},
                images=[image] if image else [],
            )
        )
        for account in accounts:
            findings.append(
                Finding(
                    source=f"Gravatar → {account['site'] or 'linked site'}",
                    category="Email",
                    status=FOUND,
                    title=account.get("username"),
                    url=account.get("url"),
                    detail="Linked from the Gravatar profile.",
                )
            )
    elif gravatar.status == 404:
        findings.append(
            Finding(
                source="Gravatar",
                category="Email",
                status=NOT_FOUND,
                detail="No Gravatar profile for this address.",
            )
        )
    else:
        findings.append(
            Finding(
                source="Gravatar",
                category="Email",
                status=BLOCKED if gravatar.blocked else ERROR,
                detail=gravatar.short_error(),
            )
        )

    if include_probes:
        # Spotify's sign-up validation endpoint discloses whether an address is taken.
        spotify = http.get(
            "https://spclient.wg.spotify.com/signup/public/v1/account",
            params={"validate": "1", "email": email},
        )
        payload = spotify.json() or {}
        if spotify.ok and payload.get("status") == 20:
            findings.append(
                Finding(
                    source="Spotify",
                    category="Email",
                    status=FOUND,
                    detail="Address is already registered on Spotify (sign-up validation response).",
                    url="https://www.spotify.com/password-reset/",
                    data={"country": payload.get("country")},
                    confidence="medium",
                )
            )
        elif spotify.ok:
            findings.append(
                Finding(
                    source="Spotify",
                    category="Email",
                    status=NOT_FOUND,
                    detail="Address is not registered on Spotify.",
                    confidence="medium",
                )
            )
        else:
            findings.append(
                Finding(
                    source="Spotify",
                    category="Email",
                    status=BLOCKED if spotify.blocked else ERROR,
                    detail=spotify.short_error(),
                )
            )

        # Duolingo exposes a public profile lookup by email for existing accounts.
        duolingo = http.get(
            "https://www.duolingo.com/2017-06-30/users",
            params={"email": email},
        )
        payload = duolingo.json() or {}
        users = payload.get("users") or []
        user = users[0] if users else {}
        if duolingo.ok and user.get("username"):
            picture = images.absolute_image_url(
                user.get("picture"), "https://www.duolingo.com"
            )
            image = None
            if picture:
                image = ImageRef(
                    url=picture,
                    alt=user.get("username") or email,
                    kind="profile",
                    page_url=f"https://www.duolingo.com/profile/{user.get('username')}",
                )
            findings.append(
                Finding(
                    source="Duolingo",
                    category="Email",
                    status=FOUND,
                    title=user.get("name") or user.get("username"),
                    detail="Address is attached to a Duolingo account.",
                    url=f"https://www.duolingo.com/profile/{user.get('username')}",
                    data={
                        "username": user.get("username"),
                        "name": user.get("name"),
                        "bio": user.get("bio"),
                        "streak": user.get("streak"),
                        "total xp": user.get("totalXp"),
                        "plus": user.get("hasPlus"),
                        "country": user.get("profileCountry"),
                        "joined": user.get("creationDate"),
                    },
                    images=[image] if image else [],
                    confidence="medium",
                )
            )
        elif duolingo.ok:
            findings.append(
                Finding(
                    source="Duolingo",
                    category="Email",
                    status=NOT_FOUND,
                    detail="No Duolingo account found for this address.",
                    confidence="medium",
                )
            )

        # GitHub user search is fuzzy (it matches terms, not the literal address),
        # so every candidate is re-checked against the profile's public email field.
        github = http.get(
            "https://api.github.com/search/users",
            params={"q": f"{email} in:email", "per_page": 10},
            headers={"Accept": "application/vnd.github+json"},
        )
        payload = github.json() or {}
        if github.ok and payload.get("total_count"):
            confirmed: list[dict[str, Any]] = []
            candidates: list[str] = []
            for item in payload.get("items", [])[:5]:
                login = item.get("login")
                if not login:
                    continue
                candidates.append(login)
                detail = http.get(
                    f"https://api.github.com/users/{login}",
                    headers={"Accept": "application/vnd.github+json"},
                )
                profile = detail.json() or {}
                public_email = (profile.get("email") or "").strip().lower()
                if detail.ok and public_email == email:
                    confirmed.append(detail.json() or item)
            for item in confirmed:
                avatar = images.absolute_image_url(
                    item.get("avatar_url"), "https://github.com"
                )
                image = None
                if avatar:
                    image = ImageRef(
                        url=avatar,
                        alt=item.get("login") or email,
                        kind="profile",
                        page_url=item.get("html_url"),
                    )
                findings.append(
                    Finding(
                        source="GitHub profile",
                        category="Email",
                        status=FOUND,
                        title=item.get("name") or item.get("login"),
                        detail="The profile publicly lists this exact email address.",
                        url=item.get("html_url"),
                        data={
                            "login": item.get("login"),
                            "name": item.get("name"),
                            "bio": item.get("bio"),
                            "company": item.get("company"),
                            "location": item.get("location"),
                            "website": item.get("blog"),
                            "twitter": item.get("twitter_username"),
                            "followers": item.get("followers"),
                            "repositories": item.get("public_repos"),
                        },
                        images=[image] if image else [],
                    )
                )
            if not confirmed:
                findings.append(
                    Finding(
                        source="GitHub search",
                        category="Email",
                        status=INFO,
                        title=f"{payload.get('total_count')} fuzzy candidate(s)",
                        detail=(
                            "GitHub's user search matches terms rather than the literal address, "
                            "and none of the checked profiles publicly lists this exact email. "
                            "Candidates below are unverified leads."
                        ),
                        data={"unverified candidates": candidates},
                    )
                )
        elif github.status == 403:
            findings.append(
                Finding(
                    source="GitHub search",
                    category="Email",
                    status=BLOCKED,
                    detail="GitHub search is rate limited. Set GITHUB_TOKEN to raise the limit.",
                )
            )
        elif github.ok:
            findings.append(
                Finding(
                    source="GitHub search",
                    category="Email",
                    status=NOT_FOUND,
                    detail="No public GitHub profile exposes this email.",
                )
            )

    # ---- Optional third-party APIs -------------------------------------
    emailrep_key = config.get("emailrep_api_key")
    if emailrep_key:
        response = http.get(f"https://emailrep.io/{email}", headers={"Key": emailrep_key})
        payload = response.json() or {}
        if response.ok:
            findings.append(
                Finding(
                    source="EmailRep",
                    category="Email",
                    status=INFO,
                    title=payload.get("reputation"),
                    detail="EmailRep reputation data.",
                    data={
                        "suspicious": payload.get("suspicious"),
                        "references": payload.get("references"),
                        "profiles": payload.get("details", {}).get("profiles", []),
                        "domain age": payload.get("details", {}).get("domain_age_days"),
                        "breach": payload.get("details", {}).get("data_breach"),
                    },
                )
            )

    if include_breaches:
        findings.extend(check_breaches(email, http, config))

    return findings
