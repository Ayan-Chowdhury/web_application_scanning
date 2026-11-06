from analyzers.headers import HeaderAnalyzer
from analyzers.tech_fingerprint import TechnologyAnalyzer
from analyzers.wordpress import WordPressAnalyzer
from analyzers.backups import BackupAnalyzer
from analyzers.robots_sitemap import RobotsSitemapAnalyzer


PASSIVE_ANALYZERS = [

    HeaderAnalyzer(),

    TechnologyAnalyzer(),

    WordPressAnalyzer(),

]


ACTIVE_SAFE_ANALYZERS = [

    BackupAnalyzer(),

    RobotsSitemapAnalyzer(),

]
# from analyzers import headers
# from analyzers import tech_fingerprint
# from analyzers import wordpress
# from analyzers import backups
# from analyzers import robots_sitemap
# from analyzers import sqli_error_based
# from analyzers import xss_reflection

# PASSIVE_ANALYZERS = [
#     headers,
#     tech_fingerprint,
#     wordpress,
# ]

# ACTIVE_SAFE_ANALYZERS = [
#     backups,
#     robots_sitemap,
# ]

# ACTIVE_RISKY_ANALYZERS = [
#     sqli_error_based,
#     xss_reflection,
# ]
