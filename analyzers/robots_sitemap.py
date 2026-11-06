from core.result import ScanResult
from analyzers.base import BaseAnalyzer


class RobotsSitemapAnalyzer(BaseAnalyzer):

    name = "Robots and Sitemap Analysis"
    category = "Information Disclosure"

    PATHS = [

        "robots.txt",
        "sitemap.xml",

    ]

    def analyze(self, target_url, response, client=None):

        results = []

        if client is None:
            return results

        base = target_url.rstrip("/")

        for path in self.PATHS:

            url = f"{base}/{path}"

            try:

                result = client.get(
                    url,
                    allow_redirects=False
                )

            except Exception:

                continue

            if result is None:
                continue

            if result.status_code != 200:
                continue

            content_type = (
                result.headers
                .get("Content-Type", "")
                .lower()
            )

            body = result.text.strip().lower()

            if (
                "text/html" in content_type
                or "<!doctype html" in body
                or "<html" in body
            ):

                continue

            if not body:
                continue

            results.append(
                ScanResult(

                    target_url=url,

                    vulnerability=f"{path} Accessible",

                    severity="Info",

                    confidence=0.95,

                    description=(
                        f"{path} is publicly accessible "
                        "and may disclose site structure."
                    ),

                    recommendation=(
                        "Review the contents and ensure "
                        "that sensitive paths are not "
                        "unnecessarily disclosed."
                    ),

                    evidence=f"Accessible resource: {url}",

                    extra={
                        "resource": path,
                        "analyzer": self.name
                    }
                )
            )

        return results
# from core.result import ScanResult

# def analyze(target_url, response, client):
#     results = []
#     base = target_url.rstrip("/")

#     for path in ["robots.txt", "sitemap.xml"]:
#         url = f"{base}/{path}"
#         r = client.get(url, allow_redirects=False)
#         if not r or r.status_code != 200:
#             continue

#         content_type = r.headers.get("Content-Type", "").lower()
#         body = r.text.strip().lower()

#         # Reject HTML custom error/login pages returned with HTTP 200
#         if "text/html" in content_type or "<!doctype html" in body or "<html" in body:
#             continue

#         if len(body) > 0:
#             results.append(
#                 ScanResult(
#                     target_url=url,
#                     vulnerability=f"{path} Found",
#                     severity="Info",
#                     confidence=0.95,
#                     description=f"{path} is accessible and may disclose internal paths.",
#                     recommendation="Review the file contents and ensure no sensitive paths are exposed.",
#                     evidence=f"Accessible: {url}"
#                 )
#             )

#     return results
