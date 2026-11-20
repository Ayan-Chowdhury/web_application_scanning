
import re
from html.parser import HTMLParser

from core.result import ScanResult


class CMSHTMLParser(HTMLParser):
    """Extract metadata and resource references from existing HTML."""

    def __init__(self):
        super().__init__()

        self.generator_values = []
        self.resource_references = []

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

        if attributes.get("name", "").lower() == "generator":
            self.generator_values.append(
                attributes.get("content", "")
            )

        for attribute in ("src", "href", "data-src"):
            value = attributes.get(attribute)

            if value:
                self.resource_references.append(value)


class MultiCMSDetector:

    name = "Multi-CMS Detector"

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

        parser = CMSHTMLParser()

        try:
            parser.feed(html)
        except Exception:
            return results

        self.checks_performed = 6

        generators = [
            value.strip()
            for value in parser.generator_values
            if value
        ]

        references = " ".join(
            parser.resource_references
        ).lower()

        html_lower = html.lower()

        detections = []

        # --------------------------------------------------
        # JOOMLA DETECTION
        # --------------------------------------------------

        joomla_generator = any(
            re.search(
                r"\bjoomla\b",
                value,
                re.IGNORECASE
            )
            for value in generators
        )

        joomla_components = bool(
            re.search(
                r"/components/com_[a-z0-9_-]+/",
                references
            )
        )

        joomla_media = (
            "/media/system/js/" in references
            or "/media/system/css/" in references
        )

        joomla_indicators = {
            "Joomla generator metadata": joomla_generator,
            "Joomla component resource": joomla_components,
            "Joomla system media resource": joomla_media,
        }

        # --------------------------------------------------
        # DRUPAL DETECTION
        # --------------------------------------------------

        drupal_generator = any(
            re.search(
                r"\bdrupal\b",
                value,
                re.IGNORECASE
            )
            for value in generators
        )

        drupal_paths = (
            "/sites/default/" in references
            or "/core/misc/" in references
        )

        drupal_settings = (
            "drupalsettings" in html_lower
            or "drupal.settings" in html_lower
        )

        drupal_indicators = {
            "Drupal generator metadata": drupal_generator,
            "Drupal resource path": drupal_paths,
            "Drupal JavaScript settings": drupal_settings,
        }

        detections.append(
            self._evaluate_cms(
                cms_name="Joomla",
                indicators=joomla_indicators,
                target_url=target_url,
                generators=generators
            )
        )

        detections.append(
            self._evaluate_cms(
                cms_name="Drupal",
                indicators=drupal_indicators,
                target_url=target_url,
                generators=generators
            )
        )

        for result in detections:
            if result is not None:
                results.append(result)

        return results

    def _evaluate_cms(
        self,
        cms_name,
        indicators,
        target_url,
        generators
    ):

        detected = [
            name
            for name, value in indicators.items()
            if value
        ]

        count = len(detected)

        if count == 0:
            return None

        generator_detected = any(
            "generator metadata" in name.lower()
            for name in detected
        )

        if generator_detected:
            confidence = 0.99
            finding = f"{cms_name} CMS Identified"
            description = (
                f"{cms_name} generator metadata was detected "
                "in the HTML response."
            )

        elif count >= 2:
            confidence = 0.90
            finding = f"Likely {cms_name} CMS Detected"
            description = (
                f"Multiple {cms_name}-related indicators were "
                "identified in the HTML response."
            )

        else:
            confidence = 0.75
            finding = f"Possible {cms_name} CMS Detected"
            description = (
                f"A {cms_name}-related indicator was identified. "
                "Additional verification is recommended."
            )

        evidence_parts = [
            f"Target URL: {target_url}",
            f"CMS: {cms_name}",
            f"Indicators detected: {count}",
        ]

        evidence_parts.extend(
            f"{indicator}: Detected"
            for indicator in detected
        )

        evidence_parts.append(
            f"Generator values: {generators}"
        )

        return ScanResult(
            target_url=target_url,
            vulnerability=finding,
            description=description,
            severity="Informational",
            confidence=confidence,
            recommendation=(
                f"Verify the {cms_name} identification through "
                "authorized administrative documentation. Keep "
                "the CMS core, themes, and extensions updated."
            ),
            evidence=" | ".join(evidence_parts),
            mechanism=(
                "Passive CMS fingerprinting using HTML generator "
                "metadata and publicly referenced CMS resources."
            ),
            analyzer=self.name,
            check=f"Passive {cms_name} identification"
        )
