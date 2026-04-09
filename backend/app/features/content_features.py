"""Page content analysis for phishing detection.

Fetches and analyzes the HTML content of a URL to detect phishing
indicators: login forms, brand impersonation, suspicious redirects,
external resource loading patterns, and visual similarity to known brands.
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import structlog

logger = structlog.get_logger(__name__)

# Brand domains and their official hostnames for comparison
BRAND_SIGNATURES = {
    "paypal": {
        "domains": ["paypal.com", "paypal.me"],
        "title_keywords": ["paypal", "pay pal"],
        "logo_alt_texts": ["paypal"],
    },
    "apple": {
        "domains": ["apple.com", "icloud.com", "appleid.apple.com"],
        "title_keywords": ["apple", "icloud", "apple id"],
        "logo_alt_texts": ["apple"],
    },
    "microsoft": {
        "domains": ["microsoft.com", "live.com", "outlook.com", "office.com"],
        "title_keywords": ["microsoft", "outlook", "office 365", "onedrive"],
        "logo_alt_texts": ["microsoft"],
    },
    "google": {
        "domains": ["google.com", "accounts.google.com", "gmail.com"],
        "title_keywords": ["google", "gmail", "sign in - google"],
        "logo_alt_texts": ["google"],
    },
    "amazon": {
        "domains": ["amazon.com", "amazon.co.uk", "aws.amazon.com"],
        "title_keywords": ["amazon", "sign in", "amazon.com"],
        "logo_alt_texts": ["amazon"],
    },
    "netflix": {
        "domains": ["netflix.com"],
        "title_keywords": ["netflix", "sign in"],
        "logo_alt_texts": ["netflix"],
    },
    "facebook": {
        "domains": ["facebook.com", "fb.com", "messenger.com"],
        "title_keywords": ["facebook", "log in", "log into facebook"],
        "logo_alt_texts": ["facebook"],
    },
    "chase": {
        "domains": ["chase.com"],
        "title_keywords": ["chase", "chase online"],
        "logo_alt_texts": ["chase"],
    },
    "wellsfargo": {
        "domains": ["wellsfargo.com"],
        "title_keywords": ["wells fargo", "sign on"],
        "logo_alt_texts": ["wells fargo"],
    },
}

# Login form indicators
LOGIN_FORM_INDICATORS = [
    'type="password"',
    "type='password'",
    'name="password"',
    'name="passwd"',
    'name="pass"',
    'name="pwd"',
    'id="password"',
    'autocomplete="current-password"',
    'autocomplete="new-password"',
]

# Suspicious form action patterns
SUSPICIOUS_ACTION_PATTERNS = [
    r"action\s*=\s*[\"']https?://[^\"']*[\"']",
    r"action\s*=\s*[\"'][^\"']*\.php[\"']",
    r"action\s*=\s*[\"']about:blank[\"']",
    r"action\s*=\s*[\"']javascript:",
]

# Phishing content keywords
PHISHING_CONTENT_KEYWORDS = {
    "verify your account",
    "confirm your identity",
    "update your payment",
    "unusual activity",
    "suspended account",
    "unauthorized access",
    "click here to verify",
    "enter your credentials",
    "confirm your password",
    "your account will be locked",
    "immediate action required",
    "security alert",
}


class ContentFeatureExtractor:
    """Analyze fetched page content for phishing indicators.

    Examines HTML structure, forms, external resources, brand presence,
    and textual content to identify phishing pages.
    """

    def __init__(self, timeout: int = 15, max_redirects: int = 5):
        self.timeout = timeout
        self.max_redirects = max_redirects

    async def extract(self, url: str, html_content: Optional[str] = None) -> Dict[str, Any]:
        """Extract content features from a URL.

        If html_content is provided, uses it directly. Otherwise, fetches
        the page content via HTTP.
        """
        features = self._default_features()

        if html_content is None:
            html_content, redirect_chain = await self._fetch_page(url)
            features["redirect_count"] = len(redirect_chain)
            features["redirect_chain"] = redirect_chain
            if redirect_chain:
                features["final_url"] = redirect_chain[-1]
        else:
            features["redirect_count"] = 0
            features["redirect_chain"] = []

        if not html_content:
            features["content_available"] = False
            return features

        features["content_available"] = True
        features["content_length"] = len(html_content)

        # Parse HTML
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, "lxml")
        except Exception as e:
            logger.warning("HTML parsing failed", url=url[:80], error=str(e))
            return features

        parsed_url = urlparse(url)
        page_domain = parsed_url.netloc.lower()

        # Title analysis
        features.update(self._analyze_title(soup, page_domain))

        # Form analysis
        features.update(self._analyze_forms(soup, page_domain))

        # Resource analysis (scripts, images, links)
        features.update(self._analyze_resources(soup, page_domain))

        # Brand detection
        features.update(self._detect_brand_impersonation(soup, page_domain, html_content))

        # Text content analysis
        features.update(self._analyze_text_content(soup))

        # Meta tag analysis
        features.update(self._analyze_meta_tags(soup))

        # Obfuscation detection
        features.update(self._detect_obfuscation(html_content))

        logger.debug(
            "Content features extracted",
            url=url[:80],
            has_login_form=features.get("has_login_form"),
            brand_score=features.get("brand_similarity_score"),
        )

        return features

    async def _fetch_page(self, url: str) -> Tuple[Optional[str], List[str]]:
        """Fetch page content following redirects."""
        redirect_chain = []
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    max_redirects=self.max_redirects,
                    allow_redirects=True,
                    ssl=False,
                    headers={"User-Agent": "Mozilla/5.0 PhishNet/1.0"},
                ) as response:
                    # Collect redirect history
                    for hist in response.history:
                        redirect_chain.append(str(hist.url))
                    if str(response.url) != url:
                        redirect_chain.append(str(response.url))

                    if response.status == 200:
                        content_type = response.headers.get("content-type", "")
                        if "text/html" in content_type:
                            return await response.text(errors="replace"), redirect_chain

        except Exception as e:
            logger.warning("Page fetch failed", url=url[:80], error=str(e))

        return None, redirect_chain

    def _analyze_title(self, soup, page_domain: str) -> Dict[str, Any]:
        """Analyze the page title for brand impersonation."""
        title_tag = soup.find("title")
        title = title_tag.get_text(strip=True) if title_tag else ""

        features = {
            "page_title": title[:200],
            "has_title": bool(title),
            "title_length": len(title),
            "page_title_match": 0.0,
        }

        if title:
            title_lower = title.lower()
            # Check if title mentions a brand not in the domain
            for brand, sig in BRAND_SIGNATURES.items():
                if any(kw in title_lower for kw in sig["title_keywords"]):
                    if not any(d in page_domain for d in sig["domains"]):
                        features["page_title_match"] = 0.9
                        features["impersonated_brand_title"] = brand
                        break

        return features

    def _analyze_forms(self, soup, page_domain: str) -> Dict[str, Any]:
        """Analyze HTML forms for login/credential harvesting indicators."""
        forms = soup.find_all("form")
        features = {
            "form_count": len(forms),
            "has_login_form": False,
            "has_password_field": False,
            "has_external_form_action": False,
            "has_empty_action": False,
            "password_field_count": 0,
            "input_field_count": 0,
            "hidden_field_count": 0,
        }

        # Check for password inputs globally
        password_inputs = soup.find_all("input", {"type": "password"})
        features["has_password_field"] = len(password_inputs) > 0
        features["password_field_count"] = len(password_inputs)
        features["has_login_form"] = len(password_inputs) > 0

        all_inputs = soup.find_all("input")
        features["input_field_count"] = len(all_inputs)
        features["hidden_field_count"] = len(
            soup.find_all("input", {"type": "hidden"})
        )

        for form in forms:
            action = form.get("action", "").strip()

            if not action or action in ("#", ".", "about:blank"):
                features["has_empty_action"] = True

            elif action.startswith(("http://", "https://")):
                action_domain = urlparse(action).netloc.lower()
                if action_domain and action_domain != page_domain:
                    features["has_external_form_action"] = True

        return features

    def _analyze_resources(self, soup, page_domain: str) -> Dict[str, Any]:
        """Analyze external resource loading patterns."""
        features = {
            "external_resource_ratio": 0.0,
            "external_script_count": 0,
            "external_link_count": 0,
            "total_links": 0,
            "null_link_count": 0,
            "self_link_count": 0,
        }

        # Analyze script sources
        scripts = soup.find_all("script", src=True)
        external_scripts = 0
        for script in scripts:
            src = script.get("src", "")
            if src.startswith(("http://", "https://")):
                src_domain = urlparse(src).netloc.lower()
                if src_domain and src_domain != page_domain:
                    external_scripts += 1
        features["external_script_count"] = external_scripts

        # Analyze anchor links
        anchors = soup.find_all("a", href=True)
        features["total_links"] = len(anchors)
        external_links = 0
        null_links = 0
        self_links = 0

        for anchor in anchors:
            href = anchor.get("href", "").strip()
            if href in ("#", "", "javascript:void(0)", "javascript:;"):
                null_links += 1
            elif href.startswith(("http://", "https://")):
                href_domain = urlparse(href).netloc.lower()
                if href_domain and href_domain != page_domain:
                    external_links += 1
                elif href_domain == page_domain:
                    self_links += 1

        features["external_link_count"] = external_links
        features["null_link_count"] = null_links
        features["self_link_count"] = self_links

        # External resource ratio
        total_resources = len(scripts) + features["total_links"]
        external_total = external_scripts + external_links
        if total_resources > 0:
            features["external_resource_ratio"] = external_total / total_resources

        return features

    def _detect_brand_impersonation(
        self, soup, page_domain: str, html_content: str
    ) -> Dict[str, Any]:
        """Detect brand impersonation by comparing page content to known brands."""
        features = {
            "brand_similarity_score": 0.0,
            "detected_brand": None,
            "brand_logo_found": False,
            "brand_favicon_mismatch": False,
        }

        html_lower = html_content.lower()
        max_score = 0.0
        detected_brand = None

        for brand, sig in BRAND_SIGNATURES.items():
            score = 0.0
            is_legitimate = any(d in page_domain for d in sig["domains"])

            if is_legitimate:
                continue

            # Check title keywords
            title = soup.find("title")
            title_text = title.get_text(strip=True).lower() if title else ""
            if any(kw in title_text for kw in sig["title_keywords"]):
                score += 0.35

            # Check for brand logos
            images = soup.find_all("img")
            for img in images:
                alt = (img.get("alt") or "").lower()
                src = (img.get("src") or "").lower()
                if any(kw in alt or kw in src for kw in sig["logo_alt_texts"]):
                    score += 0.25
                    features["brand_logo_found"] = True
                    break

            # Check body text for brand mentions
            if brand in html_lower:
                score += 0.15

            # Check for brand in CSS classes / IDs
            brand_elements = soup.find_all(
                attrs={"class": re.compile(brand, re.I)}
            )
            if brand_elements:
                score += 0.10

            # Check favicon
            favicons = soup.find_all("link", rel=re.compile("icon", re.I))
            for fav in favicons:
                href = (fav.get("href") or "").lower()
                if any(d in href for d in sig["domains"]):
                    features["brand_favicon_mismatch"] = True
                    score += 0.15
                    break

            if score > max_score:
                max_score = score
                detected_brand = brand

        features["brand_similarity_score"] = min(max_score, 1.0)
        features["detected_brand"] = detected_brand

        return features

    def _analyze_text_content(self, soup) -> Dict[str, Any]:
        """Analyze page text for phishing language patterns."""
        text = soup.get_text(separator=" ", strip=True).lower()

        features = {
            "phishing_keyword_count": 0,
            "has_urgency_language": False,
            "word_count": len(text.split()),
        }

        keyword_count = 0
        for keyword in PHISHING_CONTENT_KEYWORDS:
            if keyword in text:
                keyword_count += 1

        features["phishing_keyword_count"] = keyword_count
        features["has_urgency_language"] = keyword_count >= 2

        return features

    def _analyze_meta_tags(self, soup) -> Dict[str, Any]:
        """Analyze meta tags for suspicious patterns."""
        features = {
            "has_meta_refresh": False,
            "meta_refresh_delay": -1,
            "has_noindex": False,
        }

        # Meta refresh redirect
        meta_refresh = soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)})
        if meta_refresh:
            features["has_meta_refresh"] = True
            content = meta_refresh.get("content", "")
            try:
                delay = int(content.split(";")[0].strip())
                features["meta_refresh_delay"] = delay
            except (ValueError, IndexError):
                pass

        # Noindex (hiding from search engines)
        meta_robots = soup.find("meta", attrs={"name": re.compile("robots", re.I)})
        if meta_robots:
            content = (meta_robots.get("content") or "").lower()
            features["has_noindex"] = "noindex" in content

        return features

    def _detect_obfuscation(self, html_content: str) -> Dict[str, Any]:
        """Detect JavaScript and HTML obfuscation techniques."""
        features = {
            "has_eval": False,
            "has_unescape": False,
            "has_document_write": False,
            "has_base64_data": False,
            "obfuscation_score": 0.0,
        }

        html_lower = html_content.lower()

        if "eval(" in html_lower:
            features["has_eval"] = True
        if "unescape(" in html_lower:
            features["has_unescape"] = True
        if "document.write(" in html_lower:
            features["has_document_write"] = True
        if "base64" in html_lower or "atob(" in html_lower:
            features["has_base64_data"] = True

        score = sum([
            features["has_eval"] * 0.3,
            features["has_unescape"] * 0.3,
            features["has_document_write"] * 0.2,
            features["has_base64_data"] * 0.2,
        ])
        features["obfuscation_score"] = min(score, 1.0)

        return features

    @staticmethod
    def _default_features() -> Dict[str, Any]:
        """Return default feature values."""
        return {
            "content_available": False,
            "content_length": 0,
            "redirect_count": 0,
            "redirect_chain": [],
            "form_count": 0,
            "has_login_form": False,
            "has_password_field": False,
            "external_resource_ratio": 0.0,
            "brand_similarity_score": 0.0,
            "phishing_keyword_count": 0,
        }
