from core.result import ScanResult
from analyzers.base import BaseAnalyzer


class TechnologyAnalyzer(BaseAnalyzer):

    name = "Technology Fingerprinting"
    category = "Information Disclosure"

    def analyze(self, target_url, response, client=None):

        results = []

        if response is None:
            return results

        server = response.headers.get("Server")
        powered_by = response.headers.get("X-Powered-By")

        technologies = []

        if server:
            technologies.append(
                f"Server: {server}"
            )

        if powered_by:
            technologies.append(
                f"X-Powered-By: {powered_by}"
            )

        if not technologies:
            return results

        results.append(
            ScanResult(

                target_url=target_url,

                vulnerability="Technology Fingerprinting",

                severity="Info",

                confidence=0.95,

                description=(
                    "The server exposes technology "
                    "information through HTTP headers."
                ),

                recommendation=(
                    "Consider minimizing unnecessary "
                    "technology disclosure."
                ),

                evidence=" | ".join(technologies),

                extra={
                    "server": server,
                    "x_powered_by": powered_by,
                    "analyzer": self.name
                }
            )
        )

        return results
# from core.result import ScanResult

# def analyze(target_url, response):
#     results = []
#     if not response:
#         return results

#     server = response.headers.get("Server")
#     powered = response.headers.get("X-Powered-By")

#     tech = []
#     if server:
#         tech.append(f"Server: {server}")
#     if powered:
#         tech.append(f"X-Powered-By: {powered}")

#     if tech:
#         results.append(
#             ScanResult(
#                 target_url=target_url,
#                 vulnerability="Technology Fingerprinting",
#                 severity="Info",
#                 confidence=0.95,
#                 description="Technology stack info disclosed in headers.",
#                 recommendation="Consider removing or minimizing Server/X-Powered-By headers.",
#                 evidence=" | ".join(tech),
#                 extra={"server": server, "x_powered_by": powered}
#             )
#         )

#     return results