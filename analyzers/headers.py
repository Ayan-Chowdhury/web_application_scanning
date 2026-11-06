from core.result import ScanResult


class HeaderAnalyzer:

    name = "Header Security Analyzer"

    checks_performed = 4

    REQUIRED_HEADERS = {
        "X-Frame-Options": {
            "vulnerability": "Missing X-Frame-Options",
            "description": (
                "The HTTP response does not contain "
                "the X-Frame-Options security header."
            ),
            "recommendation": (
                "Configure X-Frame-Options or use "
                "Content-Security-Policy frame-ancestors."
            ),
            "severity": "Medium",
            "confidence": 0.85,
        },

        "Content-Security-Policy": {
            "vulnerability": "Missing Content-Security-Policy",
            "description": (
                "The HTTP response does not contain "
                "a Content-Security-Policy header."
            ),
            "recommendation": (
                "Implement a suitable Content-Security-Policy "
                "according to the application's requirements."
            ),
            "severity": "Medium",
            "confidence": 0.80,
        },

        "X-Content-Type-Options": {
            "vulnerability": "Missing X-Content-Type-Options",
            "description": (
                "The response does not contain "
                "X-Content-Type-Options."
            ),
            "recommendation": (
                "Set X-Content-Type-Options to nosniff."
            ),
            "severity": "Low",
            "confidence": 0.90,
        },

        "Referrer-Policy": {
            "vulnerability": "Missing Referrer-Policy",
            "description": (
                "The response does not define "
                "a Referrer-Policy."
            ),
            "recommendation": (
                "Configure an appropriate Referrer-Policy "
                "for the application."
            ),
            "severity": "Low",
            "confidence": 0.80,
        },
    }

    def analyze(self, response):

        findings = []

        headers = {
            key.lower(): value
            for key, value in response.headers.items()
        }

        for header, configuration in self.REQUIRED_HEADERS.items():

            if header.lower() not in headers:

                finding = ScanResult(

                    target_url=response.url,

                    vulnerability=(
                        configuration["vulnerability"]
                    ),

                    description=(
                        configuration["description"]
                    ),

                    severity=(
                        configuration["severity"]
                    ),

                    confidence=(
                        configuration["confidence"]
                    ),

                    recommendation=(
                        configuration["recommendation"]
                    ),

                    evidence=(
                        f"{header} header was not present "
                        "in the HTTP response."
                    ),

                    mechanism=(
                        "HTTP response security-header analysis"
                    ),

                    analyzer=self.name,

                    check=header
                )

                findings.append(finding)

        return findings

# from core.result import ScanResult

# REQUIRED_HEADERS = {
#     "X-Frame-Options": "Clickjacking protection missing",
#     "Content-Security-Policy": "CSP not implemented",
#     "X-Content-Type-Options": "MIME sniffing protection missing",
#     "Referrer-Policy": "Referrer policy not implemented",
#     "Permissions-Policy": "Permissions Policy not implemented"
# }

# def analyze(target_url, response):
#     results = []

#     if not response:
#         return results

#     headers_lower = {k.lower(): v for k, v in response.headers.items()}

#     for header, issue in REQUIRED_HEADERS.items():
#         if header.lower() not in headers_lower:

#             results.append(
#                 ScanResult(
#                     target_url=target_url,
#                     vulnerability="Missing Security Header",
#                     severity="Medium",
#                     confidence=0.90,
#                     description=f"{issue}: {header}",
#                     recommendation=f"Add '{header}' header in server configuration.",
#                     evidence=f"Header '{header}' not found in response."
#                 )
#             )

#     return results