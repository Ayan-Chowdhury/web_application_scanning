from core.result import ScanResult

def analyze(target_url, response):
    results = []
    if not response:
        return results

    server = response.headers.get("Server")
    powered = response.headers.get("X-Powered-By")

    tech = []
    if server:
        tech.append(f"Server: {server}")
    if powered:
        tech.append(f"X-Powered-By: {powered}")

    if tech:
        results.append(
            ScanResult(
                target_url=target_url,
                vulnerability="Technology Fingerprinting",
                severity="Info",
                confidence=0.95,
                description="Technology stack info disclosed in headers.",
                recommendation="Consider removing or minimizing Server/X-Powered-By headers.",
                evidence=" | ".join(tech),
                extra={"server": server, "x_powered_by": powered}
            )
        )

    return results