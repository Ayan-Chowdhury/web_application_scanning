from core.result import ScanResult

COMMON_BACKUPS = [
    "backup.zip",
    "backup.tar.gz",
    "site.zip",
    "www.zip",
    "public.zip",
    "db.sql",
    "database.sql",
    "dump.sql",
    ".env",
    ".env.bak",
    ".git/config"
]

def analyze(target_url, response, client):
    results = []

    base = target_url.rstrip("/")
    for name in COMMON_BACKUPS:
        url = f"{base}/{name}"

        r = client.head(url, allow_redirects=True)
        if r and r.status_code in (200, 206):
            results.append(
                ScanResult(
                    target_url=url,
                    vulnerability="Sensitive/Backup File Accessible",
                    severity="High",
                    confidence=0.80,
                    description=f"Backup or sensitive file might be publicly accessible: {name}",
                    recommendation="Remove backups from web root and restrict access.",
                    evidence=f"HEAD returned status {r.status_code}."
                )
            )

    return results