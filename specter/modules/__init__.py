"""Investigation modules. Each returns plain Finding objects."""

from .breaches import check_breaches
from .domain import investigate_domain
from .email import investigate_email
from .github import investigate_github
from .ip import investigate_ip
from .phone import investigate_phone
from .search import dork_links, dork_queries, search_all, search_web
from .username import investigate_username, load_sites

__all__ = [
    "check_breaches",
    "dork_links",
    "dork_queries",
    "investigate_domain",
    "investigate_email",
    "investigate_github",
    "investigate_ip",
    "investigate_phone",
    "investigate_username",
    "load_sites",
    "search_all",
    "search_web",
]
