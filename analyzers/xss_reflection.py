from core.result import ScanResult
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

SAFE_MARKER = "vxss_test_12345"

def analyze_url_xss(target_url, client):
    results = []

    parsed = urlparse(target_url)
    qs = parse_qs(parsed.query)

    if not qs:
        return results

    for key in list(qs.keys()):
        mutated = dict(qs)
        mutated[key] = [SAFE_MARKER]

        new_query = urlencode(mutated, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query))

        r = client.get(new_url)
        if not r:
            continue

        if SAFE_MARKER in r.text:
            results.append(
                ScanResult(
                    target_url=new_url,
                    vulnerability="Possible Reflected XSS (Reflection Detected)",
                    severity="Medium",
                    confidence=0.70,
                    description=f"Input reflection detected for parameter '{key}'.",
                    recommendation="Escape output properly and apply input validation.",
                    evidence=f"Marker '{SAFE_MARKER}' reflected in response."
                )
            )

    return results