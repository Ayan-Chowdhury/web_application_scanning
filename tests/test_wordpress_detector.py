
import unittest

from types import SimpleNamespace

from analyzers.cms import WordPressDetector


class TestWordPressDetector(unittest.TestCase):

    def setUp(self):
        self.detector = WordPressDetector()

    def make_response(self, html):
        return SimpleNamespace(
            url="http://localhost/test/",
            text=html
        )

    def test_generator_metadata(self):

        html = """
        <html>
            <head>
                <meta name="generator" content="WordPress 6.8">
            </head>
            <body>
                <h1>Local Test Page</h1>
            </body>
        </html>
        """

        response = self.make_response(html)

        results = self.detector.analyze(response)

        self.assertEqual(len(results), 1)
        self.assertEqual(
            results[0].vulnerability,
            "WordPress CMS Identified"
        )
        self.assertEqual(results[0].severity, "Informational")

    def test_multiple_wordpress_indicators(self):

        html = """
        <html>
            <head>
                <link rel="https://api.w.org/" href="/wp-json/">
                <link rel="stylesheet" href="/wp-content/style.css">
            </head>
            <body>
                <script src="/wp-includes/js/jquery.js"></script>
            </body>
        </html>
        """

        response = self.make_response(html)

        results = self.detector.analyze(response)

        self.assertEqual(len(results), 1)

        self.assertEqual(
            results[0].vulnerability,
            "Likely WordPress CMS Detected"
        )

    def test_single_indicator(self):

        html = """
        <html>
            <head>
                <link rel="stylesheet" href="/wp-content/style.css">
            </head>
        </html>
        """

        response = self.make_response(html)

        results = self.detector.analyze(response)

        self.assertEqual(len(results), 1)

        self.assertEqual(
            results[0].vulnerability,
            "Possible WordPress CMS Detected"
        )

    def test_no_wordpress_indicators(self):

        html = """
        <html>
            <head>
                <title>Local Test Website</title>
            </head>
            <body>
                <h1>Welcome</h1>
            </body>
        </html>
        """

        response = self.make_response(html)

        results = self.detector.analyze(response)

        self.assertEqual(len(results), 0)

    def test_empty_response(self):

        response = self.make_response("")

        results = self.detector.analyze(response)

        self.assertEqual(len(results), 0)

    def test_none_response(self):

        results = self.detector.analyze(None)

        self.assertEqual(len(results), 0)


if __name__ == "__main__":
    unittest.main()
