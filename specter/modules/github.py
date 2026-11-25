"""GitHub deep dive: profile, organisations, repositories, activity and commit emails."""

from __future__ import annotations

from collections import Counter
from typing import Any

from ..config import Config
from ..http import HttpClient, HttpResult
from ..models import BLOCKED, ERROR, FOUND, INFO, Finding, ImageRef

API = "https://api.github.com"
NOISE_EMAILS = {"noreply@github.com", "action@github.com", "github-actions[bot]@users.noreply.github.com"}


def _headers(config: Config) -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    token = config.get("github_token")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _get(http: HttpClient, path: str, config: Config, **kwargs: Any) -> HttpResult:
    return http.get(f"{API}{path}", headers=_headers(config), **kwargs)


def _api_error(result: HttpResult, source: str) -> Finding:
    if result.status == 404:
        return Finding(
            source=source,
            category="GitHub",
            status=ERROR,
            detail="GitHub user not found.",
        )
    if result.status in (403, 429):
        reset = result.header("x-ratelimit-reset")
        return Finding(
            source=source,
            category="GitHub",
            status=BLOCKED,
            detail=(
                "GitHub API rate limit or abuse protection triggered. "
                + (f"Resets at {reset}. " if reset else "")
                + "Set GITHUB_TOKEN to raise the limit to 5,000 requests/hour."
            ),
        )
    return Finding(
        source=source,
        category="GitHub",
        status=ERROR,
        detail=result.short_error(),
    )


def investigate_github(
    username: str,
    http: HttpClient,
    config: Config,
    *,
    repo_limit: int = 100,
) -> list[Finding]:
    username = username.strip().lstrip("@")
    findings: list[Finding] = []

    profile_result = _get(http, f"/users/{username}", config)
    if profile_result.status != 200:
        findings.append(_api_error(profile_result, "GitHub profile"))
        return findings

    user = profile_result.json() or {}
    profile = {
        "login": user.get("login"),
        "name": user.get("name"),
        "company": user.get("company"),
        "location": user.get("location"),
        "public email": user.get("email"),
        "website": user.get("blog"),
        "twitter": user.get("twitter_username"),
        "bio": user.get("bio"),
        "repositories": user.get("public_repos"),
        "gists": user.get("public_gists"),
        "followers": user.get("followers"),
        "following": user.get("following"),
        "created": user.get("created_at"),
        "updated": user.get("updated_at"),
        "hireable": user.get("hireable"),
        "account type": user.get("type"),
        "id": user.get("id"),
        "avatar": user.get("avatar_url"),
    }
    avatar = user.get("avatar_url")
    findings.append(
        Finding(
            source="GitHub profile",
            category="GitHub",
            status=FOUND,
            title=user.get("name") or user.get("login"),
            detail=(
                user.get("bio")
                or (
                    f"{user.get('public_repos', 0)} repos · "
                    f"{user.get('followers', 0)} followers"
                    + (f" · {user.get('company')}" if user.get("company") else "")
                )
            ),
            url=user.get("html_url"),
            data={key: value for key, value in profile.items() if value not in (None, "")},
            images=[
                ImageRef(
                    url=avatar,
                    alt=user.get("login") or username,
                    kind="profile",
                    page_url=user.get("html_url"),
                )
            ]
            if avatar
            else [],
        )
    )

    social = _get(http, f"/users/{username}/social_accounts", config)
    if social.status == 200:
        for account in social.json() or []:
            findings.append(
                Finding(
                    source=f"GitHub → {account.get('provider', 'social')}",
                    category="GitHub",
                    status=FOUND,
                    title=account.get("url"),
                    url=account.get("url"),
                    detail="Linked social account on the GitHub profile.",
                )
            )

    orgs = _get(http, f"/users/{username}/orgs", config, params={"per_page": 100})
    if orgs.status == 200:
        memberships = orgs.json() or []
        if memberships:
            org_images = [
                ImageRef(
                    url=org.get("avatar_url"),
                    alt=org.get("login") or "organisation",
                    kind="logo",
                    page_url=org.get("html_url"),
                )
                for org in memberships[:4]
                if org.get("avatar_url")
            ]
            findings.append(
                Finding(
                    source="GitHub organisations",
                    category="GitHub",
                    status=FOUND,
                    title=f"{len(memberships)} organisation(s)",
                    detail=", ".join(org.get("login", "") for org in memberships[:10]),
                    data={
                        "organisations": [
                            {
                                "login": org.get("login"),
                                "description": org.get("description"),
                                "url": org.get("html_url"),
                                "avatar": org.get("avatar_url"),
                            }
                            for org in memberships
                        ]
                    },
                    images=org_images,
                )
            )

    repos_result = _get(
        http,
        f"/users/{username}/repos",
        config,
        params={"per_page": min(100, repo_limit), "sort": "updated"},
    )
    if repos_result.status == 200:
        repos = repos_result.json() or []
        languages = Counter(
            repo.get("language") for repo in repos if repo.get("language")
        )
        stars = sum(int(repo.get("stargazers_count") or 0) for repo in repos)
        ordered_repos = sorted(
            repos,
            key=lambda repo: (
                int(repo.get("stargazers_count") or 0),
                repo.get("pushed_at") or "",
            ),
            reverse=True,
        )
        if repos:
            findings.append(
                Finding(
                    source="GitHub repositories",
                    category="GitHub",
                    status=FOUND,
                    title=f"{len(repos)} repository(ies)",
                    detail=(
                        f"{stars:,} stars · languages: "
                        + ", ".join(name for name, _ in languages.most_common(5))
                    ),
                    data={
                        "repository count": len(repos),
                        "total stars": stars,
                        "languages": dict(languages.most_common(10)),
                        "repository list": [
                            {
                                "name": repo.get("name"),
                                "full name": repo.get("full_name"),
                                "description": repo.get("description"),
                                "language": repo.get("language"),
                                "stars": repo.get("stargazers_count"),
                                "forks": repo.get("forks_count"),
                                "watchers": repo.get("watchers_count"),
                                "open issues": repo.get("open_issues_count"),
                                "size KB": repo.get("size"),
                                "default branch": repo.get("default_branch"),
                                "license": (repo.get("license") or {}).get("spdx_id"),
                                "topics": repo.get("topics"),
                                "homepage": repo.get("homepage"),
                                "created": repo.get("created_at"),
                                "updated": repo.get("updated_at"),
                                "pushed": repo.get("pushed_at"),
                                "archived": repo.get("archived"),
                                "fork": repo.get("fork"),
                                "visibility": repo.get("visibility"),
                                "url": repo.get("html_url"),
                            }
                            for repo in ordered_repos
                        ],
                    },
                )
            )

    events_result = _get(
        http,
        f"/users/{username}/events/public",
        config,
        params={"per_page": 100},
    )
    if events_result.status == 200:
        events = events_result.json() or []
        if events:
            event_types = Counter(event.get("type") for event in events)
            repos_touched = {
                (event.get("repo") or {}).get("name")
                for event in events
                if (event.get("repo") or {}).get("name")
            }
            findings.append(
                Finding(
                    source="GitHub activity",
                    category="GitHub",
                    status=FOUND,
                    title=f"{len(events)} recent public event(s)",
                    detail=(
                        f"last {events[0].get('created_at', 'unknown')} · "
                        + ", ".join(f"{name} ×{count}" for name, count in event_types.most_common(4))
                    ),
                    data={
                        "repositories touched": sorted(repos_touched)[:25],
                        "event types": dict(event_types),
                        "latest event": events[0].get("created_at"),
                        "activity": [
                            {
                                "type": event.get("type"),
                                "repo": (event.get("repo") or {}).get("name"),
                                "date": event.get("created_at"),
                                "action": (event.get("payload") or {}).get("action"),
                                "ref": (event.get("payload") or {}).get("ref"),
                                "ref type": (event.get("payload") or {}).get("ref_type"),
                                "commits": len(
                                    (event.get("payload") or {}).get("commits") or []
                                ),
                                "title": (
                                    ((event.get("payload") or {}).get("issue") or {}).get("title")
                                    or ((event.get("payload") or {}).get("pull_request") or {}).get("title")
                                ),
                                "number": (
                                    ((event.get("payload") or {}).get("issue") or {}).get("number")
                                    or ((event.get("payload") or {}).get("pull_request") or {}).get("number")
                                ),
                            }
                            for event in events
                        ],
                    },
                )
            )

            emails: dict[str, dict[str, Any]] = {}
            for event in events:
                repo_name = (event.get("repo") or {}).get("name") or ""
                payload = event.get("payload") or {}
                commits = list(payload.get("commits") or [])
                head = payload.get("head_commit")
                if head:
                    commits.append(head)
                for commit in commits:
                    author = (commit or {}).get("author") or {}
                    email = (author.get("email") or "").strip().lower()
                    if not email or email in NOISE_EMAILS or "@" not in email:
                        continue
                    entry = emails.setdefault(
                        email, {"name": author.get("name"), "repos": set(), "count": 0}
                    )
                    entry["count"] += 1
                    if repo_name:
                        entry["repos"].add(repo_name)
            if not emails:
                # PushEvent payloads no longer include commits; read the commit
                # history of the most active repositories instead.
                repo_names = [
                    (event.get("repo") or {}).get("name")
                    for event in events
                    if (event.get("repo") or {}).get("name")
                ]
                seen_repos: list[str] = []
                for name in repo_names:
                    if name and name not in seen_repos:
                        seen_repos.append(name)
                for repo_name in seen_repos[:4]:
                    commits_result = _get(
                        http,
                        f"/repos/{repo_name}/commits",
                        config,
                        params={"author": username, "per_page": 10},
                    )
                    if commits_result.status != 200:
                        continue
                    for commit in commits_result.json() or []:
                        author = (commit.get("commit") or {}).get("author") or {}
                        email_value = (author.get("email") or "").strip().lower()
                        if not email_value or email_value in NOISE_EMAILS or "@" not in email_value:
                            continue
                        entry = emails.setdefault(
                            email_value,
                            {"name": author.get("name"), "repos": set(), "count": 0},
                        )
                        entry["count"] += 1
                        entry["repos"].add(repo_name)

            for email, entry in sorted(emails.items()):
                findings.append(
                    Finding(
                        source="GitHub commit email",
                        category="GitHub",
                        status=FOUND,
                        title=email,
                        detail=(
                            f"{entry['name'] or 'unknown author'} · "
                            f"{', '.join(sorted(entry['repos'])[:3])}"
                        ),
                        data={
                            "commits sampled": entry["count"],
                            "repositories": sorted(entry["repos"])[:10],
                        },
                    )
                )

    remaining = profile_result.header("x-ratelimit-remaining")
    if remaining and remaining.isdigit() and int(remaining) < 10 and not config.get("github_token"):
        findings.append(
            Finding(
                source="GitHub API quota",
                category="GitHub",
                status=INFO,
                detail=(
                    f"{remaining} unauthenticated requests left in this window. "
                    "Set GITHUB_TOKEN for deeper scans."
                ),
            )
        )

    return findings
