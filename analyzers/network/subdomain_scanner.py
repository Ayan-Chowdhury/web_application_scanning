from urllib.parse import urlparse

import requests

from core.results import ScanResult


class SubdomainScanner:

    name = "Subdomain Scanner"

    SUBDOMAINS = [
        "www",
        "mail",
        "api",
        "dev",
        "test",
        "staging",
        "admin",
        "portal",
        "app",
        "blog",
        "docs",
        "cdn",
    ]

    def __init__(self, timeout=5):

        self.timeout = timeout
        self.checks_performed = 0

    def analyze(self, response):

        results = []

        self.checks_performed = 0

        if response is None:
            return results

        base_url = getattr(
            response,
            "url",
            None
        )

        if not base_url:
            return results

        parsed = urlparse(base_url)

        hostname = parsed.hostname

        if not hostname:
            return results

        # Avoid trying to enumerate localhost/IP targets
        if self._is_ip_address(hostname):
            return results

        scheme = parsed.scheme or "https"

        for subdomain in self.SUBDOMAINS:

            self.checks_performed += 1

            target = f"{subdomain}.{hostname}"

            url = f"{scheme}://{target}"

            try:

                result = requests.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=True
                )

                if result.status_code < 500:

                    results.append(
                        ScanResult(
                            target_url=url,

                            vulnerability="Subdomain Discovered",

                            description=(
                                f"The subdomain "
                                f"{target} responded to an HTTP request."
                            ),

                            severity="Info",

                            confidence=0.90,

                            recommendation=(
                                "Review the discovered subdomain "
                                "and ensure it is intentionally exposed."
                            ),

                            evidence=(
                                f"HTTP response received from {url} "
                                f"with status code "
                                f"{result.status_code}."
                            ),

                            mechanism=(
                                "Controlled subdomain enumeration "
                                "using HTTP response analysis."
                            ),

                            analyzer=self.name,

                            check=(
                                f"HTTP reachability of "
                                f"{target}"
                            ),

                            extra={
                                "status_code": result.status_code,
                                "hostname": target
                            }
                        )
                    )

            except requests.RequestException:
                continue

        return results

    @staticmethod
    def _is_ip_address(hostname):

        parts = hostname.split(".")

        if len(parts) != 4:
            return False

        try:

            return all(
                0 <= int(part) <= 255
                for part in parts
            )

        except ValueError:

            return False