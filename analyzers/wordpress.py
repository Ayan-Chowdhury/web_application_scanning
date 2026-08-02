from core.result import ScanResult

WP_MARKERS = [
    "/wp-content/",
    "/wp-includes/"
]

def analyze(target_url, response):
    results = []
    if not response:
        return results

    html = response.text.lower()

    found = any(marker in html for marker in WP_MARKERS)

    if found:
        results.append(
            ScanResult(
                target_url=target_url,
                vulnerability="WordPress Detected",
                severity="Info",
                confidence=0.85,
                description="The target appears to be running WordPress.",
                recommendation="Ensure WordPress core, themes, and plugins are updated.",
                evidence="Found wp-content/wp-includes markers in HTML."
            )
        )

    return results