"""Heuristic feature extraction for the browser-extension URL detector."""

from __future__ import annotations

import ipaddress
from typing import Dict, Iterable
from urllib.parse import urlparse


SHORTENER_DOMAINS = {
    "adf.ly",
    "bit.do",
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "t.co",
    "tiny.cc",
    "tinyurl.com",
}

POPULAR_DOMAINS = {
    "amazon.com",
    "apple.com",
    "facebook.com",
    "github.com",
    "google.com",
    "linkedin.com",
    "microsoft.com",
    "netflix.com",
    "openai.com",
    "paypal.com",
    "wikipedia.org",
    "youtube.com",
}

SUSPICIOUS_TLDS = {
    ".buzz",
    ".cf",
    ".club",
    ".ga",
    ".gq",
    ".ml",
    ".tk",
    ".top",
    ".xyz",
}

SUSPICIOUS_KEYWORDS = {
    "account",
    "bank",
    "confirm",
    "credential",
    "login",
    "password",
    "secure",
    "signin",
    "suspend",
    "update",
    "verify",
    "wallet",
}


def ensure_url_scheme(url: str) -> str:
    """Normalize inbound URLs so parsing stays predictable."""
    value = url.strip()
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    return value


def extract_features(url: str, feature_order: Iterable[str]) -> Dict[str, int]:
    """Return dataset-aligned feature values for a single URL."""
    normalized_url = ensure_url_scheme(url)
    parsed = urlparse(normalized_url)
    hostname = (parsed.hostname or "").lower()
    netloc = (parsed.netloc or "").lower()
    query = parsed.query or ""
    url_lower = normalized_url.lower()

    has_ip = _has_ip_address(hostname)
    suspicious_tld = any(hostname.endswith(suffix) for suffix in SUSPICIOUS_TLDS)
    is_shortener = any(hostname == domain or hostname.endswith(f".{domain}") for domain in SHORTENER_DOMAINS)
    subdomain_count = max(len([part for part in hostname.split(".") if part]) - 2, 0)
    popular_domain = any(hostname == domain or hostname.endswith(f".{domain}") for domain in POPULAR_DOMAINS)
    explicit_port = parsed.port
    double_slash_after_scheme = "//" in normalized_url.split("://", 1)[-1]
    phishy_terms = sum(keyword in url_lower for keyword in SUSPICIOUS_KEYWORDS)

    derived = {
        "having_IP_Address": -1 if has_ip else 1,
        "URL_Length": _bucket_url_length(len(normalized_url)),
        "Shortining_Service": -1 if is_shortener else 1,
        "having_At_Symbol": -1 if "@" in normalized_url else 1,
        "double_slash_redirecting": -1 if double_slash_after_scheme else 1,
        "Prefix_Suffix": -1 if "-" in hostname else 1,
        "having_Sub_Domain": _bucket_subdomains(subdomain_count),
        "SSLfinal_State": 1 if parsed.scheme == "https" else -1,
        "Domain_registeration_length": -1 if suspicious_tld or is_shortener else 1,
        "Favicon": 1,
        "port": -1 if _has_nonstandard_port(parsed.scheme, explicit_port) else 1,
        "HTTPS_token": -1 if "https" in hostname.replace("https", "", 1) else 1,
        "Request_URL": -1 if phishy_terms >= 2 else (0 if phishy_terms == 1 else 1),
        "URL_of_Anchor": -1 if "redirect=" in url_lower or "url=" in url_lower else 1,
        "Links_in_tags": 0 if query else 1,
        "SFH": -1 if "mailto:" in url_lower else 1,
        "Submitting_to_email": -1 if "mailto:" in url_lower or "email=" in url_lower else 1,
        "Abnormal_URL": -1 if not hostname or "@" in netloc else 1,
        "Redirect": -1 if "redirect" in url_lower or "next=" in url_lower else 0,
        "on_mouseover": 1,
        "RightClick": 1,
        "popUpWidnow": 1,
        "Iframe": 1,
        "age_of_domain": -1 if suspicious_tld or is_shortener else (1 if popular_domain else 0),
        "DNSRecord": 1 if hostname and not has_ip else -1,
        "web_traffic": 1 if popular_domain else (-1 if suspicious_tld else 0),
        "Page_Rank": 1 if popular_domain else (-1 if has_ip or suspicious_tld else 0),
        "Google_Index": 1 if popular_domain else (-1 if suspicious_tld or has_ip else 0),
        "Links_pointing_to_page": 1 if popular_domain else 0,
        "Statistical_report": -1 if has_ip or is_shortener or suspicious_tld or phishy_terms >= 2 else 1,
    }

    return {column: int(derived.get(column, 0)) for column in feature_order}


def _has_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _bucket_url_length(length: int) -> int:
    if length < 54:
        return 1
    if length <= 75:
        return 0
    return -1


def _bucket_subdomains(count: int) -> int:
    if count <= 1:
        return 1
    if count == 2:
        return 0
    return -1


def _has_nonstandard_port(scheme: str, port: int | None) -> bool:
    if port is None:
        return False
    default_port = 443 if scheme == "https" else 80
    return port != default_port
