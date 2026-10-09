"""
Feature Extraction Module for Phishing Website Detection System.
Extracts lexical and structural characteristics from URL strings.
Used consistently for both dataset preparation and real-time prediction.
"""

import re
import urllib.parse
from typing import Dict, Any, List, Tuple

# Ordered list of feature names used for ML model training and inference
FEATURE_NAMES: List[str] = [
    "url_length",
    "has_https",
    "count_dots",
    "count_hyphens",
    "count_special_chars",
    "count_digits",
    "has_ip_address",
    "suspicious_word_count",
    "count_subdomains",
    "has_at_symbol",
    "is_shortened",
    "prefix_suffix_hyphen",
    "has_double_slash_redirect"
]

# HTTPS is useful to display, but should not determine the phishing verdict.
MODEL_FEATURE_NAMES: List[str] = [
    name for name in FEATURE_NAMES if name != "has_https"
]

# Common URL shortening domains often leveraged by phishing attacks
SHORTENING_SERVICES = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "is.gd", "buff.ly",
    "ow.ly", "rebrand.ly", "cutt.ly", "tiny.cc", "tr.im", "v.gd"
}

# Suspicious keywords frequently observed in credential harvesting URLs
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "banking",
    "signin", "admin", "password", "confirm", "billing", "wallet",
    "ebayisapi", "webscr", "pay", "recover", "authenticate", "auth"
]

# Regular expression pattern to detect IPv4 addresses in hostname
IPV4_PATTERN = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"


def normalize_url(raw_url: str) -> str:
    """
    Sanitize and normalize URL input string without fetching or contacting the website.
    """
    if not raw_url:
        return ""
    url = raw_url.strip()
    # Strip any accidental wrapping whitespace or quotes
    url = url.strip("\"'<>")
    # If no protocol is provided, prefix with http:// for reliable parsing
    if not url.lower().startswith(("http://", "https://", "ftp://")):
        url = "http://" + url
    return url


def extract_features(raw_url: str) -> Dict[str, Any]:
    """
    Extract numeric feature vector dictionary matching FEATURE_NAMES.
    """
    url = normalize_url(raw_url)
    if not url:
        # Return zeros if empty
        return {name: 0 for name in FEATURE_NAMES}

    try:
        parsed = urllib.parse.urlsplit(url)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path.lower()
    except Exception:
        hostname = ""
        path = ""

    # 1. URL Length: Phishers often create long obfuscated URLs
    url_length = len(url)

    # 2. HTTPS Presence: Authentic secure websites predominantly use HTTPS
    has_https = 1 if url.lower().startswith("https://") else 0

    # 3. Dots count: Multiple dots can signify deep subdomains or file extension masquerading
    count_dots = url.count(".")

    # 4. Hyphens count: Hyphens are frequently added to spoof reputable brand names (e.g. paypal-login)
    count_hyphens = url.count("-")

    # 5. Special characters count
    special_chars = set("@?=_#%+&$!*~;")
    count_special_chars = sum(1 for char in url if char in special_chars)

    # 6. Digits count: Obfuscated hex, token, or IP-style numbers in URL
    count_digits = sum(1 for char in url if char.isdigit())

    # 7. Presence of IP Address in Hostname
    has_ip = 1 if re.match(IPV4_PATTERN, hostname) else 0

    # 8. Suspicious keywords count across the whole URL
    url_lower = url.lower()
    suspicious_count = sum(1 for word in SUSPICIOUS_KEYWORDS if word in url_lower)

    # 9. Subdomains count (e.g. www.paypal.secure-login.com -> 3 parts -> 2 subdomains)
    subdomain_parts = [part for part in hostname.split(".") if part and part != "www"]
    count_subdomains = max(0, len(subdomain_parts) - 2) if len(subdomain_parts) > 2 else 0

    # 10. Presence of '@' symbol: Browser ignores string prior to @, sending user to destination after @
    has_at_symbol = 1 if "@" in url else 0

    # 11. URL Shortening service
    is_shortened = 1 if hostname in SHORTENING_SERVICES else 0

    # 12. Prefix/Suffix hyphen in domain (e.g., netflix-secure.com)
    prefix_suffix_hyphen = 1 if "-" in hostname else 0

    # 13. Double slash redirection after protocol (e.g., http://example.com//evil.com)
    has_double_slash = 1 if "//" in path else 0

    return {
        "url_length": int(url_length),
        "has_https": int(has_https),
        "count_dots": int(count_dots),
        "count_hyphens": int(count_hyphens),
        "count_special_chars": int(count_special_chars),
        "count_digits": int(count_digits),
        "has_ip_address": int(has_ip),
        "suspicious_word_count": int(suspicious_count),
        "count_subdomains": int(count_subdomains),
        "has_at_symbol": int(has_at_symbol),
        "is_shortened": int(is_shortened),
        "prefix_suffix_hyphen": int(prefix_suffix_hyphen),
        "has_double_slash_redirect": int(has_double_slash)
    }


def extract_features_vector(raw_url: str) -> List[int]:
    """
    Returns feature values as an ordered numeric list matching FEATURE_NAMES.
    """
    feat_dict = extract_features(raw_url)
    return [feat_dict[name] for name in FEATURE_NAMES]


def get_display_features(raw_url: str) -> List[Dict[str, Any]]:
    """
    Returns human-friendly feature descriptions and statuses for UI display.
    """
    feats = extract_features(raw_url)
    
    return [
        {
            "name": "URL Length",
            "value": f"{feats['url_length']} characters",
            "status": "Safe" if feats['url_length'] < 75 else "Suspicious",
            "is_risk": feats['url_length'] >= 75,
            "description": "Legitimate URLs are generally under 75 characters. Excessively long URLs are often obfuscated."
        },
        {
            "name": "HTTPS Encryption",
            "value": "Yes (HTTPS)" if feats['has_https'] == 1 else "No (Insecure HTTP)",
            "status": "Safe" if feats['has_https'] == 1 else "Suspicious",
            "is_risk": feats['has_https'] == 0,
            "description": "Standard websites employ TLS/HTTPS encryption to protect user communication."
        },
        {
            "name": "Dot Count (.)",
            "value": f"{feats['count_dots']} dots",
            "status": "Safe" if feats['count_dots'] <= 3 else "Suspicious",
            "is_risk": feats['count_dots'] > 3,
            "description": "More than 3 dots often indicates deep subdomain nesting or deceptive routing."
        },
        {
            "name": "Hyphen Count (-)",
            "value": f"{feats['count_hyphens']} hyphens",
            "status": "Safe" if feats['count_hyphens'] <= 1 else "Suspicious",
            "is_risk": feats['count_hyphens'] > 1,
            "description": "Attackers insert hyphens to mimic authentic domain names (e.g. apple-login)."
        },
        {
            "name": "Special Characters",
            "value": f"{feats['count_special_chars']} found",
            "status": "Safe" if feats['count_special_chars'] <= 2 else "Suspicious",
            "is_risk": feats['count_special_chars'] > 2,
            "description": "High count of symbols like @, ?, =, %, & often conceals exploit payloads or redirects."
        },
        {
            "name": "Digits in URL",
            "value": f"{feats['count_digits']} digits",
            "status": "Safe" if feats['count_digits'] <= 5 else "Suspicious",
            "is_risk": feats['count_digits'] > 5,
            "description": "Excessive numerical sequences are common in dynamically generated phishing pages."
        },
        {
            "name": "IP Address Usage",
            "value": "Detected" if feats['has_ip_address'] == 1 else "None (Domain Name)",
            "status": "Suspicious" if feats['has_ip_address'] == 1 else "Safe",
            "is_risk": feats['has_ip_address'] == 1,
            "description": "Using an IP address instead of a domain name is a strong indicator of malicious hosting."
        },
        {
            "name": "Suspicious Keywords",
            "value": f"{feats['suspicious_word_count']} detected",
            "status": "Suspicious" if feats['suspicious_word_count'] > 0 else "Safe",
            "is_risk": feats['suspicious_word_count'] > 0,
            "description": "Keywords like 'login', 'verify', 'update', 'banking' often target credential harvesting."
        },
        {
            "name": "Subdomain Complexity",
            "value": f"{feats['count_subdomains']} subdomains",
            "status": "Safe" if feats['count_subdomains'] <= 1 else "Suspicious",
            "is_risk": feats['count_subdomains'] > 1,
            "description": "Excessive subdomains are used by threat actors to disguise malicious secondary domains."
        },
        {
            "name": "Presence of '@' Symbol",
            "value": "Detected" if feats['has_at_symbol'] == 1 else "Not Present",
            "status": "Suspicious" if feats['has_at_symbol'] == 1 else "Safe",
            "is_risk": feats['has_at_symbol'] == 1,
            "description": "The '@' symbol leads browsers to ignore the preceding text and connect to the following host."
        },
        {
            "name": "URL Shortener Service",
            "value": "Yes" if feats['is_shortened'] == 1 else "No",
            "status": "Suspicious" if feats['is_shortened'] == 1 else "Safe",
            "is_risk": feats['is_shortened'] == 1,
            "description": "URL shortening hides the actual destination host, frequently concealing phishing links."
        },
        {
            "name": "Domain Hyphen Prefix/Suffix",
            "value": "Yes" if feats['prefix_suffix_hyphen'] == 1 else "No",
            "status": "Suspicious" if feats['prefix_suffix_hyphen'] == 1 else "Safe",
            "is_risk": feats['prefix_suffix_hyphen'] == 1,
            "description": "Hyphens inside domain names are rarely used by prominent legitimate organizations."
        },
        {
            "name": "Double Slash Redirection",
            "value": "Detected" if feats['has_double_slash_redirect'] == 1 else "Normal",
            "status": "Suspicious" if feats['has_double_slash_redirect'] == 1 else "Safe",
            "is_risk": feats['has_double_slash_redirect'] == 1,
            "description": "Double slashes '//' within the path can force silent redirects to rogue destination servers."
        }
    ]
