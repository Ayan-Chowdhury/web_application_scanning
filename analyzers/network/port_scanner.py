
import socket
from urllib.parse import urlparse
from datetime import datetime, timezone

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
    Performs limited TCP connectivity checks.

    Only use against systems you own or are authorized to assess.
    No authentication or exploitation is performed.
    """

    name = "Port Scanner"

    def __init__(self, timeout=1.0, ports=None):
        self.timeout = timeout
        self.ports = (
            list(COMMON_PORTS.keys())
            if ports is None
            else list(ports)
        )
        self.checks_performed = 0

    def _extract_hostname(self, target_url):
        parsed = urlparse(target_url)
        return parsed.hostname

    def _resolve_host(self, hostname):
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

    def _check_port(self, ip_address, port):
        try:
            with socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            ) as sock:

                sock.settimeout(self.timeout)

                return sock.connect_ex(
                    (ip_address, port)
                ) == 0

        except OSError:
            return False

    def analyze(self, response):

        findings = []
        self.checks_performed = 0

        if response is None:
            return findings

        target_url = response.url
        hostname = self._extract_hostname(target_url)

        if not hostname:
            return findings

        ip_address = self._resolve_host(hostname)

        if not ip_address:
            findings.append(
                ScanResult(
                    target_url=target_url,
                    vulnerability="Host Resolution Failure",
                    description=(
                        "The target hostname could not "
                        "be resolved to an IP address."
                    ),
                    severity="Informational",
                    confidence=1.0,
                    recommendation=(
                        "Verify the target hostname and DNS resolution."
                    ),
                    evidence=f"Hostname: {hostname}",
                    mechanism="DNS hostname resolution",
                    analyzer=self.name,
                    check="Host DNS resolution",
                )
            )
            return findings

        open_ports = []

        for port in self.ports:

            self.checks_performed += 1

            if self._check_port(ip_address, port):
                open_ports.append(port)

        scan_time = datetime.now(timezone.utc).isoformat()

        # Record each accessible service as an observation.
        for port in open_ports:

            service = COMMON_PORTS.get(port, "Unknown")

            # An open port alone does not prove a vulnerability.
            severity = "Informational"

            findings.append(
                ScanResult(
                    target_url=target_url,
                    vulnerability="Accessible Network Service",
                    description=(
                        f"TCP port {port} ({service}) "
                        "accepted a connection from the scanner."
                    ),
                    severity=severity,
                    confidence=0.95,
                    recommendation=(
                        "Verify whether this service is intended "
                        "to be accessible from the scanner's network. "
                        "Apply network restrictions where appropriate."
                    ),
                    evidence=(
                        f"Hostname: {hostname} | "
                        f"Resolved IP: {ip_address} | "
                        f"Port: {port} | "
                        f"Service: {service} | "
                        f"Protocol: TCP | "
                        f"Observed at: {scan_time}"
                    ),
                    mechanism="TCP connection reachability check",
                    analyzer=self.name,
                    check=f"TCP port {port}",
                )
            )

        if not open_ports:

            findings.append(
                ScanResult(
                    target_url=target_url,
                    vulnerability="No Commonly Monitored Services Reachable",
                    description=(
                        "No commonly monitored TCP ports "
                        "were reachable from the scanner."
                    ),
                    severity="Informational",
                    confidence=0.90,
                    recommendation=(
                        "Continue monitoring network exposure "
                        "and maintain appropriate firewall restrictions."
                    ),
                    evidence=(
                        f"Hostname: {hostname} | "
                        f"Resolved IP: {ip_address} | "
                        f"Ports checked: {self.checks_performed} | "
                        f"Observed at: {scan_time}"
                    ),
                    mechanism="TCP connection reachability check",
                    analyzer=self.name,
                    check="Common TCP ports",
                )
            )

        return findings


# import socket
# from urllib.parse import urlparse
#
# from core.result import ScanResult
#
#
# COMMON_PORTS = {
#     21: "FTP",
#     22: "SSH",
#     23: "Telnet",
#     25: "SMTP",
#     53: "DNS",
#     80: "HTTP",
#     110: "POP3",
#     143: "IMAP",
#     443: "HTTPS",
#     445: "SMB",
#     587: "SMTP Submission",
#     993: "IMAPS",
#     995: "POP3S",
#     1433: "MSSQL",
#     1521: "Oracle",
#     3306: "MySQL",
#     3389: "RDP",
#     5432: "PostgreSQL",
#     6379: "Redis",
#     8080: "HTTP Alternate",
#     8443: "HTTPS Alternate",
# }
#
#
# class PortScanner:
#     """
#     Performs a limited TCP connect scan against the target host.
#
#     This analyzer identifies exposed TCP services.
#     It does not attempt authentication or exploitation.
#     """
#
#     name = "Port Scanner"
#
#     def __init__(self, timeout=1.0, ports=None):
#
#         self.timeout = timeout
#
#         if ports is None:
#             self.ports = list(COMMON_PORTS.keys())
#         else:
#             self.ports = ports
#
#     def _extract_hostname(self, target_url):
#
#         parsed = urlparse(target_url)
#
#         if parsed.hostname:
#             return parsed.hostname
#
#         return target_url
#
#     def _resolve_host(self, hostname):
#
#         try:
#             return socket.gethostbyname(hostname)
#
#         except socket.gaierror:
#
#             return None
#
#     def _check_port(self, hostname, port):
#
#         sock = socket.socket(
#             socket.AF_INET,
#             socket.SOCK_STREAM
#         )
#
#         sock.settimeout(self.timeout)
#
#         try:
#
#             result = sock.connect_ex(
#                 (hostname, port)
#             )
#
#             return result == 0
#
#         except OSError:
#
#             return False
#
#         finally:
#
#             sock.close()
#
#     def analyze(self, target_url):
#
#         findings = []
#
#         hostname = self._extract_hostname(
#             target_url
#         )
#
#         ip_address = self._resolve_host(
#             hostname
#         )
#
#         if not ip_address:
#
#             findings.append(
#                 ScanResult(
#                     target_url=target_url,
#                     description=(
#                         "The target hostname could not "
#                         "be resolved to an IP address."
#                     ),
#                     vulnerability="Host Resolution Failure",
#                     severity="Informational",
#                     confidence=1.0,
#                     recommendation=(
#                         "Verify that the target hostname "
#                         "is correct and DNS resolution is available."
#                     ),
#                     evidence=(
#                         f"Hostname: {hostname}"
#                     ),
#                 )
#             )
#
#             return findings
#
#         open_ports = []
#
#         for port in self.ports:
#
#             if self._check_port(
#                 hostname,
#                 port
#             ):
#
#                 open_ports.append(port)
#
#         for port in open_ports:
#
#             service = COMMON_PORTS.get(
#                 port,
#                 "Unknown"
#             )
#
#             findings.append(
#                 ScanResult(
#                     target_url=target_url,
#                     description=(
#                         f"TCP port {port} is accessible "
#                         f"on the target host."
#                     ),
#                     vulnerability="Exposed Network Service",
#                     severity="Low",
#                     confidence=0.95,
#                     recommendation=(
#                         "Verify that this service is required. "
#                         "Restrict unnecessary services using "
#                         "firewall rules or network controls."
#                     ),
#                     evidence=(
#                         f"Host: {hostname} | "
#                         f"IP: {ip_address} | "
#                         f"Port: {port} | "
#                         f"Service: {service} | "
#                         f"Protocol: TCP"
#                     ),
#                 )
#             )
#
#         if not open_ports:
#
#             findings.append(
#                 ScanResult(
#                     target_url=target_url,
#                     description=(
#                         "No commonly monitored TCP ports "
#                         "were reachable."
#                     ),
#                     vulnerability="No Commonly Exposed Services",
#                     severity="Informational",
#                     confidence=0.90,
#                     recommendation=(
#                         "Continue monitoring exposed services "
#                         "and maintain firewall restrictions."
#                     ),
#                     evidence=(
#                         f"Host: {hostname} | "
#                         f"IP: {ip_address} | "
#                         f"Ports checked: {len(self.ports)}"
#                     ),
#                 )
#             )
#
#         return findings