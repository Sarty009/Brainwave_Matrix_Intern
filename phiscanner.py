import re
import requests
from urllib.parse import urlparse

def check_blacklist(url):
    """Check URL against OpenPhish or PhishTank (Requires API key for full access)."""
    try:
        response = requests.get(f"https://openphish.com/feed.txt")
        if url in response.text:
            return True
    except requests.exceptions.RequestException:
        pass
    return False

def has_suspicious_keywords(url):
    """Detects suspicious keywords commonly used in phishing attacks."""
    suspicious_keywords = ["login", "verify", "update", "secure", "banking", "account"]
    return any(keyword in url.lower() for keyword in suspicious_keywords)

def lexical_analysis(url):
    """Detects lexical patterns common in phishing URLs."""
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    if domain.count('-') > 2:  # Too many hyphens
        return True
    if domain.count('.') > 3:  # Excessive subdomains
        return True
    return False

def check_google_safe_browsing(url, api_key):
    """Check URL against Google Safe Browsing API."""
    payload = {"client": {"clientId": "phishing-scanner", "clientVersion": "1.0"},
               "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                              "platformTypes": ["ANY_PLATFORM"],
                              "threatEntryTypes": ["URL"],
                              "threatEntries": [{"url": url}]}}
    try:
        response = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}", json=payload)
        return response.json().get("matches") is not None
    except requests.exceptions.RequestException:
        return False

def phishing_scan(url, api_key=None):
    """Runs all phishing detection checks."""
    if check_blacklist(url):
        return "⚠️ Blacklisted: This is a known phishing site!"
    if has_suspicious_keywords(url):
        return "⚠️ Suspicious Keywords: This URL contains phishing-related words."
    if lexical_analysis(url):
        return "⚠️ Lexical Warning: This URL has patterns often used in phishing."
    if api_key and check_google_safe_browsing(url, api_key):
        return "⚠️ Google Safe Browsing Alert: URL is flagged as unsafe."
    return "✅ Safe: No phishing indicators detected."

if __name__ == "__main__":
    test_url = input("Enter a URL to scan: ")
    api_key = "YOUR_GOOGLE_API_KEY"  # Optional Google Safe Browsing API Key
    result = phishing_scan(test_url, api_key)
    print(result)
