
import re
from html.parser import HTMLParser

from core.result import ScanResult


class WordPressHTMLParser(HTMLParser):
    """
    Extract WordPress-related indicators from existing HTML.

    This parser does not make network requests.
    """

    def __init__(self):
        super().__init__()

        self.generator_values = []
        self.resource_references = []
        self.api_relations = []

    def handle_starttag(self, tag, attrs):
        self._process_tag(attrs)

    def handle_startendtag(self, tag, attrs):
        self._process_tag(attrs)

    def _process_tag(self, attrs):
        attributes = {
            key.lower(): value
            for key, value in attrs
            if key and value is not None
        }

        # Generator metadata
        if (
            attributes.get("name", "").lower() == "generator"
        ):
            self.generator_values.append(
                attributes.get("content", "")
            )

        # Resource references
        for attribute in ("src", "href", "data-src"):
            value = attributes.get(attribute)

            if value:
                self.resource_references.append(value)

        # WordPress REST API relation
        rel = attributes.get("rel", "").lower()
        href = attributes.get("href", "").lower()

        if "api.w.org" in rel or "api.w.org" in href:
            self.api_relations.append(href or rel)


class WordPressDetector:

    name = "WordPress Detector"

    def __init__(self):
        self.checks_performed = 0

    def analyze(self, response):

        results = []
        self.checks_performed = 0

        if response is None:
            return results

        target_url = getattr(response, "url", None)
        html = getattr(response, "text", None)

        if not target_url or not html:
            return results

        # Five passive detection checks.
        self.checks_performed = 5

        parser = WordPressHTMLParser()

        try:
            parser.feed(html)
        except Exception:
            return results

        indicators = {}

        # --------------------------------------------------
        # 1. WordPress generator metadata
        # --------------------------------------------------

        generator_detected = any(
            re.match(
                r"^\s*WordPress(?:\s|$)",
                value,
                re.IGNORECASE
            )
            for value in parser.generator_values
        )

        indicators["generator_metadata"] = generator_detected

        # --------------------------------------------------
        # 2. WordPress content directory
        # --------------------------------------------------

        all_references = " ".join(
            parser.resource_references
        ).lower()

        content_detected = "/wp-content/" in all_references

        indicators["wp_content"] = content_detected

        # --------------------------------------------------
        # 3. WordPress includes directory
        # --------------------------------------------------

        includes_detected = "/wp-includes/" in all_references

        indicators["wp_includes"] = includes_detected

        # --------------------------------------------------
        # 4. WordPress REST API relation
        # --------------------------------------------------

        api_detected = bool(parser.api_relations)

        indicators["wordpress_api_relation"] = api_detected

        # --------------------------------------------------
        # 5. WordPress REST API path reference
        # --------------------------------------------------

        wp_json_detected = bool(
            re.search(
                r"/wp-json(?:/|\b|\?|#)",
                html,
                re.IGNORECASE
            )
        )

        indicators["wp_json_reference"] = wp_json_detected

        # --------------------------------------------------
        # Evaluate detection confidence
        # --------------------------------------------------

        detected_indicators = [
            name
            for name, detected in indicators.items()
            if detected
        ]

        indicator_count = len(detected_indicators)

        if indicator_count == 0:
            return results

        # Explicit generator metadata is the strongest signal.
        if generator_detected:
            confidence = 0.99
            finding_name = "WordPress CMS Identified"
            description = (
                "WordPress generator metadata was detected "
                "in the HTML response."
            )

        elif indicator_count >= 2:
            confidence = 0.90
            finding_name = "Likely WordPress CMS Detected"
            description = (
                "Multiple WordPress-related indicators were "
                "identified in the HTML response."
            )

        else:
            confidence = 0.75
            finding_name = "Possible WordPress CMS Detected"
            description = (
                "A WordPress-related indicator was identified. "
                "Further verification is required."
            )

        # --------------------------------------------------
        # Evidence
        # --------------------------------------------------

        evidence_parts = [
            f"Target URL: {target_url}",
            f"Indicators detected: {indicator_count}",
        ]

        for indicator in detected_indicators:
            evidence_parts.append(
                f"{indicator}: Detected"
            )

        evidence_parts.append(
            f"Generator values: {parser.generator_values}"
        )

        evidence_parts.append(
            f"Observed indicators: {', '.join(detected_indicators)}"
        )

        evidence = " | ".join(evidence_parts)

        # --------------------------------------------------
        # Recommendation
        # --------------------------------------------------

        recommendation = (
            "Verify the CMS identification through authorized "
            "administrative documentation. Keep the CMS core, "
            "themes, and extensions updated, and review the "
            "organization's CMS security configuration."
        )

        results.append(
            ScanResult(
                target_url=target_url,
                vulnerability=finding_name,
                description=description,
                severity="Informational",
                confidence=confidence,
                recommendation=recommendation,
                evidence=evidence,
                mechanism=(
                    "Passive CMS fingerprinting through HTML "
                    "metadata and publicly referenced WordPress "
                    "resource indicators."
                ),
                analyzer=self.name,
                check="Five passive WordPress identification indicators"
            )
        )

        return results
