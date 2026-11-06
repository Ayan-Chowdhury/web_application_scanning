from core.result import ScanResult
from analyzers.base import BaseAnalyzer


class BackupAnalyzer(BaseAnalyzer):

    name = "Backup File Detection"
    category = "Security Misconfiguration"

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

        ".git/config",
    ]

    def analyze(self, target_url, response, client=None):

        results = []

        if client is None:
            return results

        base = target_url.rstrip("/")

        for filename in self.COMMON_BACKUPS:

            url = f"{base}/{filename}"

            try:

                result = client.head(
                    url,
                    allow_redirects=False
                )

            except Exception:
                continue

            if result is None:
                continue

            if result.status_code not in (200, 206):
                continue

            content_type = (
                result.headers
                .get("Content-Type", "")
                .lower()
            )

            if "text/html" in content_type:
                continue

            results.append(
                ScanResult(

                    target_url=url,

                    vulnerability=(
                        "Sensitive/Backup File Accessible"
                    ),

                    severity="High",

                    confidence=0.80,

                    description=(
                        f"The potential backup or sensitive "
                        f"file '{filename}' appears accessible."
                    ),

                    recommendation=(
                        "Remove unnecessary backup files "
                        "from the web root and restrict "
                        "access to sensitive resources."
                    ),

                    evidence=(
                        f"HTTP HEAD returned "
                        f"{result.status_code} for {url}."
                    ),

                    extra={
                        "filename": filename,
                        "status_code": result.status_code,
                        "content_type": content_type,
                        "analyzer": self.name
                    }
                )
            )

        return results
# from core.result import ScanResult

# COMMON_BACKUPS = [
#     "backup.zip",
#     "backup.tar.gz",
#     "site.zip",
#     "www.zip",
#     "public.zip",
#     "db.sql",
#     "database.sql",
#     "dump.sql",
#     ".env",
#     ".env.bak",
#     ".git/config"
# ]

# def analyze(target_url, response, client):
#     results = []

#     base = target_url.rstrip("/")
#     for name in COMMON_BACKUPS:
#         url = f"{base}/{name}"

#         # Do not follow redirects (e.g. 302 redirect to /login/)
#         r = client.head(url, allow_redirects=False)
#         if r and r.status_code in (200, 206):
#             content_type = r.headers.get("Content-Type", "").lower()
#             # If server returns HTML for non-existent files with 200 OK
#             if "text/html" in content_type:
#                 continue

#             results.append(
#                 ScanResult(
#                     target_url=url,
#                     vulnerability="Sensitive/Backup File Accessible",
#                     severity="High",
#                     confidence=0.80,
#                     description=f"Backup or sensitive file might be publicly accessible: {name}",
#                     recommendation="Remove backups from web root and restrict access.",
#                     evidence=f"HEAD returned status {r.status_code}."
#                 )
#             )

#     return results
