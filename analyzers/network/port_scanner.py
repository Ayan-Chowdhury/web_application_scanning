import socket
from urllib.parse import urlparse

from core.result import ScanResult


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate",
}


class PortScanner:
    """
    Performs a limited TCP connect scan against the target host.

    This analyzer identifies exposed TCP services.
    It does not attempt authentication or exploitation.
    """

    name = "Port Scanner"

    def __init__(self, timeout=1.0, ports=None):

        self.timeout = timeout

        if ports is None:
            self.ports = list(COMMON_PORTS.keys())
        else:
            self.ports = ports

    def _extract_hostname(self, target_url):

        parsed = urlparse(target_url)

        if parsed.hostname:
            return parsed.hostname

        return target_url

    def _resolve_host(self, hostname):

        try:
            return socket.gethostbyname(hostname)

        except socket.gaierror:

            return None

    def _check_port(self, hostname, port):

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(self.timeout)

        try:

            result = sock.connect_ex(
                (hostname, port)
            )

            return result == 0

        except OSError:

            return False

        finally:

            sock.close()

    def analyze(self, target_url):

        findings = []

        hostname = self._extract_hostname(
            target_url
        )

        ip_address = self._resolve_host(
            hostname
        )

        if not ip_address:

            findings.append(
                ScanResult(
                    target_url=target_url,
                    description=(
                        "The target hostname could not "
                        "be resolved to an IP address."
                    ),
                    vulnerability="Host Resolution Failure",
                    severity="Informational",
                    confidence=1.0,
                    recommendation=(
                        "Verify that the target hostname "
                        "is correct and DNS resolution is available."
                    ),
                    evidence=(
                        f"Hostname: {hostname}"
                    ),
                )
            )

            return findings

        open_ports = []

        for port in self.ports:

            if self._check_port(
                hostname,
                port
            ):

                open_ports.append(port)

        for port in open_ports:

            service = COMMON_PORTS.get(
                port,
                "Unknown"
            )

            findings.append(
                ScanResult(
                    target_url=target_url,
                    description=(
                        f"TCP port {port} is accessible "
                        f"on the target host."
                    ),
                    vulnerability="Exposed Network Service",
                    severity="Low",
                    confidence=0.95,
                    recommendation=(
                        "Verify that this service is required. "
                        "Restrict unnecessary services using "
                        "firewall rules or network controls."
                    ),
                    evidence=(
                        f"Host: {hostname} | "
                        f"IP: {ip_address} | "
                        f"Port: {port} | "
                        f"Service: {service} | "
                        f"Protocol: TCP"
                    ),
                )
            )

        if not open_ports:

            findings.append(
                ScanResult(
                    target_url=target_url,
                    description=(
                        "No commonly monitored TCP ports "
                        "were reachable."
                    ),
                    vulnerability="No Commonly Exposed Services",
                    severity="Informational",
                    confidence=0.90,
                    recommendation=(
                        "Continue monitoring exposed services "
                        "and maintain firewall restrictions."
                    ),
                    evidence=(
                        f"Host: {hostname} | "
                        f"IP: {ip_address} | "
                        f"Ports checked: {len(self.ports)}"
                    ),
                )
            )

        return findings