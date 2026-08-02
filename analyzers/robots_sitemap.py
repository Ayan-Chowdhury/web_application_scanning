from core.result import ScanResult

def analyze(target_url, response, client):
    results = []
    base = target_url.rstrip("/")

    for path in ["robots.txt", "sitemap.xml"]:
        url = f"{base}/{path}"
        r = client.get(url)
        if r and r.status_code == 200 and len(r.text.strip()) > 0:
            results.append(
                ScanResult(
                    target_url=url,
                    vulnerability=f"{path} Found",
                    severity="Info",
                    confidence=0.95,
                    description=f"{path} is accessible and may disclose internal paths.",
                    recommendation="Review the file contents and ensure no sensitive paths are exposed.",
                    evidence=f"Accessible: {url}"
                )
            )

    return results