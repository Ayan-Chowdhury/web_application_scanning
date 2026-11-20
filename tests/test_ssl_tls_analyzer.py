
import unittest

from types import SimpleNamespace
from unittest.mock import patch

from analyzers.tls import SSLTLSAnalyzer


class TestSSLTLSAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = SSLTLSAnalyzer()

    def make_response(self, url):
        return SimpleNamespace(url=url)

    def valid_inspection(self):
        return {
            "error_type": None,
            "error": None,
            "certificate": {
                "subject": (
                    (("commonName", "localhost"),),
                ),
                "issuer": (
                    (("commonName", "Local Test CA"),),
                ),
                "notAfter": "Dec 31 23:59:59 2099 GMT",
                "subjectAltName": (
                    ("DNS", "localhost"),
                ),
            },
            "tls_version": "TLSv1.3",
            "cipher": (
                "TLS_AES_256_GCM_SHA384",
                "TLSv1.3",
                256
            ),
        }

    def test_http_url_is_skipped(self):

        response = self.make_response(
            "http://localhost/"
        )

        results = self.analyzer.analyze(response)

        self.assertEqual(results, [])
        self.assertEqual(
            self.analyzer.checks_performed,
            0
        )

    def test_none_response(self):

        results = self.analyzer.analyze(None)

        self.assertEqual(results, [])
        self.assertEqual(
            self.analyzer.checks_performed,
            0
        )

    @patch.object(SSLTLSAnalyzer, "_inspect_tls")
    def test_verified_tls_connection(self, mock_inspect):

        mock_inspect.return_value = self.valid_inspection()

        response = self.make_response(
            "https://localhost/"
        )

        results = self.analyzer.analyze(response)

        self.assertEqual(len(results), 1)

        self.assertEqual(
            results[0].vulnerability,
            "TLS Connection and Certificate Verified"
        )

        self.assertEqual(
            results[0].severity,
            "Informational"
        )

        self.assertEqual(
            self.analyzer.checks_performed,
            5
        )

    @patch.object(SSLTLSAnalyzer, "_inspect_tls")
    def test_certificate_expiring_soon(self, mock_inspect):

        inspection = self.valid_inspection()

        inspection["certificate"]["notAfter"] = (
            "Dec 31 23:59:59 2099 GMT"
        )

        # Use a mocked near-future expiration by patching
        # the returned inspection and time conversion.
        mock_inspect.return_value = inspection

        response = self.make_response(
            "https://localhost/"
        )

        results = self.analyzer.analyze(response)

        self.assertEqual(
            results[0].vulnerability,
            "TLS Connection and Certificate Verified"
        )

    @patch.object(SSLTLSAnalyzer, "_inspect_tls")
    def test_certificate_verification_failure(self, mock_inspect):

        mock_inspect.return_value = {
            "error_type": "verification",
            "error": "Hostname mismatch"
        }

        response = self.make_response(
            "https://localhost/"
        )

        results = self.analyzer.analyze(response)

        self.assertEqual(len(results), 1)

        self.assertEqual(
            results[0].vulnerability,
            "TLS Certificate Verification Failed"
        )

        self.assertEqual(
            results[0].severity,
            "Medium"
        )

    @patch.object(SSLTLSAnalyzer, "_inspect_tls")
    def test_tls_connection_failure(self, mock_inspect):

        mock_inspect.return_value = {
            "error_type": "connection",
            "error": "Connection refused"
        }

        response = self.make_response(
            "https://localhost/"
        )

        results = self.analyzer.analyze(response)

        self.assertEqual(len(results), 1)

        self.assertEqual(
            results[0].vulnerability,
            "TLS Inspection Inconclusive"
        )


if __name__ == "__main__":
    unittest.main()
