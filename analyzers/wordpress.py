from core.result import ScanResult
from analyzers.base import BaseAnalyzer


class WordPressAnalyzer(BaseAnalyzer):

    name = "WordPress Detection"
    category = "Technology Detection"

    WP_MARKERS = [

        "/wp-content/",

        "/wp-includes/",

    ]

    def analyze(self, target_url, response, client=None):

        results = []

        if response is None:
            return results

        html = response.text.lower()

        found_markers = []

        for marker in self.WP_MARKERS:

            if marker in html:

                found_markers.append(marker)

        if not found_markers:

            return results

        results.append(
            ScanResult(

                target_url=target_url,

                vulnerability="WordPress Detected",

                severity="Info",

                confidence=0.85,

                description=(
                    "The target appears to use "
                    "WordPress."
                ),

                recommendation=(
                    "Keep WordPress core, themes and "
                    "plugins updated."
                ),

                evidence=(
                    "Detected markers: "
                    + ", ".join(found_markers)
                ),

                extra={
                    "markers": found_markers,
                    "analyzer": self.name
                }
            )
        )

        return results
# from core.result import ScanResult

# WP_MARKERS = [
#     "/wp-content/",
#     "/wp-includes/"
# ]

# def analyze(target_url, response):
#     results = []
#     if not response:
#         return results

#     html = response.text.lower()

#     found = any(marker in html for marker in WP_MARKERS)

#     if found:
#         results.append(
#             ScanResult(
#                 target_url=target_url,
#                 vulnerability="WordPress Detected",
#                 severity="Info",
#                 confidence=0.85,
#                 description="The target appears to be running WordPress.",
#                 recommendation="Ensure WordPress core, themes, and plugins are updated.",
#                 evidence="Found wp-content/wp-includes markers in HTML."
#             )
#         )

#     return results