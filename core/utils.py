from urllib.parse import urlparse, urlunparse

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    cleaned = parsed._replace(fragment="")
    return urlunparse(cleaned).rstrip("/")