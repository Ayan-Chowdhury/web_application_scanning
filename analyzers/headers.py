from core.result import ScanResult

REQUIRED_HEADERS = {
    "X-Frame-Options": "Clickjacking protection missing",
    "Content-Security-Policy": "CSP not implemented",
    "X-Content-Type-Options": "MIME sniffing protection missing",
}

def analyze_headers(response):
    results = []

    for header, issue in REQUIRED_HEADERS.items():
        if header not in response.headers:
            results.append(
                ScanResult(
                    target_url=response.url,
                    vulnerability="Security Header Missing",
                    severity="Medium",
                    confidence=0.85,
                    description=issue,
                    recommendation=f"Add {header} header",
                )
            )
    return results
