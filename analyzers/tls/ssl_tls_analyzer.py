import socket
import ssl

from datetime import datetime, timezone
from urllib.parse import urlparse

from core.result import ScanResult


class SSLTLSAnalyzer:
    name = "SSL/TLS Security Analyzer"

    def __init__(self, timeout=5):
        self.timeout = timeout
        self.checks_performed = 0

    def _inspect_tls(self, hostname, port):
        """
        Establish one certificate-verified TLS connection.

        No certificate verification is disabled or bypassed.
        """

        context = ssl.create_default_context()

        try:
            with socket.create_connection(
                    (hostname, port),
                    timeout=self.timeout
            ) as raw_socket:

                with context.wrap_socket(
                        raw_socket,
                        server_hostname=hostname
                ) as tls_socket:
                    return {
                        "error_type": None,
                        "error": None,
                        "certificate": tls_socket.getpeercert(),
                        "tls_version": tls_socket.version(),
                        "cipher": tls_socket.cipher(),
                    }

        except ssl.SSLCertVerificationError as exc:

            return {
                "error_type": "verification",
                "error": getattr(
                    exc,
                    "verify_message",
                    str(exc)
                ),
            }

        except (ssl.SSLError, OSError, socket.timeout) as exc:

            return {
                "error_type": "connection",
                "error": str(exc),
            }

    @staticmethod
    def _format_distinguished_name(value):

        parts = []

        for group in value or []:
            for key, item in group:
                parts.append(f"{key}={item}")

        return ", ".join(parts)

    def _create_result(self,target_url,finding,description,severity,confidence,recommendation,evidence,check):

        return ScanResult(
            target_url=target_url,
            vulnerability=finding,
            description=description,
            severity=severity,
            confidence=confidence,
            recommendation=recommendation,
            evidence=evidence,
            mechanism=(
                "TLS certificate and connection inspection "
                "using Python's verified SSL context."
            ),
            analyzer=self.name,
            check=check
        )

    def analyze(self, response):

        results = []
        self.checks_performed = 0

        if response is None:
            return results

        target_url = getattr(response, "url", None)

        if not target_url:
            return results

        parsed = urlparse(target_url)

        # Only inspect HTTPS URLs.
        if parsed.scheme.lower() != "https":
            return results

        hostname = parsed.hostname

        if not hostname:
            return results

        try:
            port = parsed.port or 443
        except ValueError:
            return results

        # One TLS inspection operation.
        self.checks_performed = 1

        inspection = self._inspect_tls(
            hostname,
            port
        )

        # --------------------------------------------------
        # Certificate verification failure
        # --------------------------------------------------

        if inspection.get("error_type") == "verification":
            error = inspection.get("error") or (
                "Certificate verification failed."
            )

            results.append(
                self._create_result(
                    target_url=target_url,
                    finding="TLS Certificate Verification Failed",
                    description=(
                        "The TLS connection could not be verified "
                        "using the system certificate trust settings."
                    ),
                    severity="Medium",
                    confidence=0.95,
                    recommendation=(
                        "Review the certificate validity, hostname "
                        "configuration, certificate chain, and "
                        "trusted certificate authority configuration."
                    ),
                    evidence=(
                        f"Hostname: {hostname} | "
                        f"Port: {port} | "
                        f"Verification Error: {error}"
                    ),
                    check="TLS certificate and hostname verification"
                )
            )

            return results

        # --------------------------------------------------
        # Connection or TLS negotiation failure
        # --------------------------------------------------

        if inspection.get("error_type") == "connection":
            error = inspection.get("error") or (
                "TLS connection could not be established."
            )

            results.append(
                self._create_result(
                    target_url=target_url,
                    finding="TLS Inspection Inconclusive",
                    description=(
                        "The analyzer could not complete a verified "
                        "TLS connection. This does not independently "
                        "establish a certificate vulnerability."
                    ),
                    severity="Informational",
                    confidence=0.95,
                    recommendation=(
                        "Verify HTTPS availability, network connectivity, "
                        "and server-side TLS configuration."
                    ),
                    evidence=(
                        f"Hostname: {hostname} | "
                        f"Port: {port} | "
                        f"Inspection Error: {error}"
                    ),
                    check="TLS connection establishment"
                )
            )

            return results

        # --------------------------------------------------
        # Successfully verified TLS connection
        # --------------------------------------------------

        self.checks_performed = 5

        certificate = inspection.get("certificate") or {}

        tls_version = inspection.get("tls_version") or "Unknown"

        cipher = inspection.get("cipher")

        cipher_name = (
            cipher[0]
            if cipher and len(cipher) > 0
            else "Unknown"
        )

        issuer = self._format_distinguished_name(
            certificate.get("issuer")
        )

        subject = self._format_distinguished_name(
            certificate.get("subject")
        )

        not_after = certificate.get("notAfter")

        expiration_date = "Unavailable"
        remaining_days = None

        if not_after:
            expiration_timestamp = ssl.cert_time_to_seconds(
                not_after
            )

            expiration_datetime = datetime.fromtimestamp(
                expiration_timestamp,
                tz=timezone.utc
            )

            current_datetime = datetime.now(timezone.utc)

            remaining_seconds = (
                    expiration_datetime - current_datetime
            ).total_seconds()

            remaining_days = int(
                remaining_seconds // 86400
            )

            expiration_date = expiration_datetime.isoformat()

        subject_alt_names = certificate.get(
            "subjectAltName",
            []
        )

        san_values = [
            value
            for name, value in subject_alt_names
            if name == "DNS"
        ]

        evidence = (
            f"Hostname: {hostname} | "
            f"Port: {port} | "
            f"TLS Version: {tls_version} | "
            f"Cipher: {cipher_name} | "
            f"Certificate Subject: {subject} | "
            f"Certificate Issuer: {issuer} | "
            f"Certificate Expiration: {expiration_date} | "
            f"Remaining Days: {remaining_days} | "
            f"Hostname Verification: Passed | "
            f"Certificate Verification: Passed | "
            f"DNS SAN Entries: {san_values}"
        )

        # --------------------------------------------------
        # Main successful TLS observation
        # --------------------------------------------------

        results.append(
            self._create_result(
                target_url=target_url,
                finding="TLS Connection and Certificate Verified",
                description=(
                    "A TLS connection was successfully established. "
                    "The certificate chain and hostname were verified "
                    "using the system trust configuration."
                ),
                severity="Informational",
                confidence=1.0,
                recommendation=(
                    "Continue monitoring certificate expiration and "
                    "maintain a secure TLS configuration."
                ),
                evidence=evidence,
                check="TLS certificate and connection inspection"
            )
        )

        # --------------------------------------------------
        # Certificate expiration warning
        # --------------------------------------------------

        if remaining_days is not None:

            if remaining_days <= 7:

                results.append(
                    self._create_result(
                        target_url=target_url,
                        finding="TLS Certificate Expiring Soon",
                        description=(
                            "The verified TLS certificate expires "
                            "within seven days."
                        ),
                        severity="Medium",
                        confidence=1.0,
                        recommendation=(
                            "Arrange certificate renewal promptly "
                            "to avoid HTTPS service interruption."
                        ),
                        evidence=evidence,
                        check="TLS certificate expiration"
                    )
                )

            elif remaining_days <= 30:

                results.append(
                    self._create_result(
                        target_url=target_url,
                        finding="TLS Certificate Expiring Soon",
                        description=(
                            "The verified TLS certificate expires "
                            "within thirty days."
                        ),
                        severity="Low",
                        confidence=1.0,
                        recommendation=(
                            "Schedule certificate renewal before "
                            "the expiration date."
                        ),
                        evidence=evidence,
                        check="TLS certificate expiration"
                    )
                )

        return results
