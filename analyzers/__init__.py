from analyzers import headers
from analyzers import tech_fingerprint
from analyzers import wordpress
from analyzers import backups
from analyzers import robots_sitemap
from analyzers import sqli_error_based
from analyzers import xss_reflection

PASSIVE_ANALYZERS = [
    headers,
    tech_fingerprint,
    wordpress,
]

ACTIVE_SAFE_ANALYZERS = [
    backups,
    robots_sitemap,
]

ACTIVE_RISKY_ANALYZERS = [
    sqli_error_based,
    xss_reflection,
]
