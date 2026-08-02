from core.result import ScanResult

REQUIRED_HEADERS = {
    "X-Frame-Options": "Clickjacking protection missing",
    "Content-Security-Policy": "CSP not implemented",
    "X-Content-Type-Options": "MIME sniffing protection missing",
    "Referrer-Policy": "Referrer policy not implemented",
    "Permissions-Policy": "Permissions Policy not implemented"
}

def analyze(target_url, response):
    results = []

    if not response:
        return results

    headers_lower = {k.lower(): v for k, v in response.headers.items()}

    for header, issue in REQUIRED_HEADERS.items():
        if header.lower() not in headers_lower:

            results.append(
                ScanResult(
                    target_url=target_url,
                    vulnerability="Missing Security Header",
                    severity="Medium",
                    confidence=0.90,
                    description=f"{issue}: {header}",
                    recommendation=f"Add '{header}' header in server configuration.",
                    evidence=f"Header '{header}' not found in response."
                )
            )

    return results