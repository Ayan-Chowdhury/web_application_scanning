
import ipaddress
import socket
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from core.result import ScanResult


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

        # Overall checks = DNS lookups + HTTP requests.
        self.checks_performed = 0

        # Separate metrics for accurate reporting.
        self.dns_checks_performed = 0
        self.http_checks_performed = 0

    @staticmethod
    def _is_ip_address(hostname):
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False

    @staticmethod
    def _get_base_domain(hostname):
        """
        Supports a root hostname or its www-prefixed form.
        This is intentionally not a Public Suffix List implementation.
        """
        hostname = hostname.lower().rstrip(".")

        if hostname.startswith("www."):
            return hostname[4:]

        return hostname

    def _resolve_candidate(self, hostname):
        """Resolve a hostname and return its unique IP addresses."""
        self.dns_checks_performed += 1

        try:
            records = socket.getaddrinfo(
                hostname,
                None,
                type=socket.SOCK_STREAM
            )

            addresses = {
                record[4][0]
                for record in records
                if record[4]
            }

            return sorted(addresses)

        except socket.gaierror:
            return []

        except OSError:
            return []

    def _detect_wildcard_dns(self, base_domain):
        """
        Resolve two unpredictable hostnames.
        Matching non-empty results indicate possible wildcard DNS.
        """
        first_label = f"scanner-check-{uuid.uuid4().hex[:12]}"
        second_label = f"scanner-check-{uuid.uuid4().hex[:12]}"

        first_addresses = self._resolve_candidate(
            f"{first_label}.{base_domain}"
        )

        second_addresses = self._resolve_candidate(
            f"{second_label}.{base_domain}"
        )

        wildcard_detected = (
            bool(first_addresses)
            and first_addresses == second_addresses
        )

        return wildcard_detected, set(first_addresses)

    def _check_http_response(self, hostname):
        """
        Check HTTP reachability only after DNS resolution.
        HTTPS is attempted first; HTTP is a fallback.
        """
        for scheme in ("https", "http"):
            url = f"{scheme}://{hostname}"

            self.http_checks_performed += 1

            try:
                response = requests.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=True,
                    headers={
                        "User-Agent": "Modern-Vulnerability-Scanner/1.0"
                    }
                )

                return url, response.status_code

            except requests.RequestException:
                continue

        return None, None

    def _create_result(
        self,
        base_domain,
        hostname,
        addresses,
        http_url,
        status_code
    ):
        timestamp = datetime.now(timezone.utc).isoformat()

        if status_code is not None:
            http_evidence = (
                f"HTTP URL: {http_url} | "
                f"HTTP Status: {status_code}"
            )
            description = (
                f"The hostname {hostname} resolved to DNS addresses "
                f"and returned an HTTP response with status {status_code}."
            )
        else:
            http_evidence = "HTTP response: Not received"
            description = (
                f"The hostname {hostname} resolved to DNS addresses, "
                "but no HTTP response was received over HTTPS or HTTP."
            )

        evidence = (
            f"Base Domain: {base_domain} | "
            f"Hostname: {hostname} | "
            f"DNS Addresses: {', '.join(addresses)} | "
            f"{http_evidence} | "
            f"Observed at: {timestamp}"
        )

        return ScanResult(
            target_url=http_url or f"https://{hostname}",
            vulnerability="Subdomain Discovered",
            description=description,
            severity="Informational",
            confidence=0.95,
            recommendation=(
                "Verify that this hostname is expected, properly managed, "
                "and covered by the organization's security controls."
            ),
            evidence=evidence,
            mechanism=(
                "Controlled subdomain candidate resolution using DNS, "
                "followed by a limited HTTP reachability check."
            ),
            analyzer=self.name,
            check=f"DNS resolution of {hostname}"
        )

    def analyze(self, response):
        results = []

        self.checks_performed = 0
        self.dns_checks_performed = 0
        self.http_checks_performed = 0

        if response is None:
            return results

        response_url = getattr(response, "url", None)

        if not response_url:
            return results

        parsed = urlparse(response_url)
        original_hostname = (parsed.hostname or "").lower().rstrip(".")

        if not original_hostname:
            return results

        if self._is_ip_address(original_hostname):
            return results

        if original_hostname == "localhost":
            return results

        base_domain = self._get_base_domain(original_hostname)

        # Avoid treating nested hostnames as root domains.
        # Public suffix-aware normalization is intentionally not included.
        if base_domain.count(".") < 1:
            return results

        # Check for wildcard DNS before evaluating candidates.
        wildcard_detected, wildcard_addresses = (
            self._detect_wildcard_dns(base_domain)
        )

        for label in self.SUBDOMAINS:
            candidate = f"{label}.{base_domain}"

            # Never report the original input hostname as discovered.
            if candidate == original_hostname:
                continue

            # Do not report the base domain as a discovered subdomain.
            if candidate == base_domain:
                continue

            addresses = self._resolve_candidate(candidate)

            if not addresses:
                continue

            # Suppress candidates that match the wildcard DNS response.
            if wildcard_detected and set(addresses) == wildcard_addresses:
                continue

            http_url, status_code = self._check_http_response(candidate)

            results.append(
                self._create_result(
                    base_domain=base_domain,
                    hostname=candidate,
                    addresses=addresses,
                    http_url=http_url,
                    status_code=status_code
                )
            )

        self.checks_performed = (
            self.dns_checks_performed + self.http_checks_performed
        )

        return results
