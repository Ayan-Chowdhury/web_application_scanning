
import unittest
from types import SimpleNamespace

from analyzers.cms import MultiCMSDetector


class TestMultiCMSDetector(unittest.TestCase):

    def setUp(self):
        self.detector = MultiCMSDetector()

    def make_response(self, html):
        return SimpleNamespace(
            url="http://localhost/test/",
            text=html
        )

    def test_joomla_generator(self):

        html = """
        <html>
            <head>
                <meta name="generator" content="Joomla! - Open Source CMS">
            </head>
        </html>
        """

        results = self.detector.analyze(
            self.make_response(html)
        )

        self.assertEqual(len(results), 1)
        self.assertEqual(
            results[0].vulnerability,
            "Joomla CMS Identified"
        )

    def test_joomla_resource_indicators(self):

        html = """
        <html>
            <head>
                <script src="/components/com_content/js/content.js"></script>
                <script src="/media/system/js/core.js"></script>
            </head>
        </html>
        """

        results = self.detector.analyze(
            self.make_response(html)
        )

        self.assertEqual(len(results), 1)
        self.assertEqual(
            results[0].vulnerability,
            "Likely Joomla CMS Detected"
        )

    def test_drupal_generator(self):

        html = """
        <html>
            <head>
                <meta name="generator" content="Drupal 11">
            </head>
        </html>
        """

        results = self.detector.analyze(
            self.make_response(html)
        )

        self.assertEqual(len(results), 1)
        self.assertEqual(
            results[0].vulnerability,
            "Drupal CMS Identified"
        )

    def test_drupal_resource_indicators(self):

        html = """
        <html>
            <head>
                <script src="/core/misc/drupal.js"></script>
                <script src="/sites/default/files/js/site.js"></script>
            </head>
            <body>
                <script>
                    drupalSettings = {};
                </script>
            </body>
        </html>
        """

        results = self.detector.analyze(
            self.make_response(html)
        )

        self.assertEqual(len(results), 1)
        self.assertEqual(
            results[0].vulnerability,
            "Likely Drupal CMS Detected"
        )

    def test_no_cms_indicators(self):

        html = """
        <html>
            <head>
                <title>Local Test</title>
            </head>
            <body>
                <h1>Hello World</h1>
            </body>
        </html>
        """

        results = self.detector.analyze(
            self.make_response(html)
        )

        self.assertEqual(len(results), 0)

    def test_none_response(self):

        results = self.detector.analyze(None)

        self.assertEqual(len(results), 0)


if __name__ == "__main__":
    unittest.main()
