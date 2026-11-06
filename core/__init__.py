# from core.http_client import HttpClient
# from core.crawler import WebCrawler
# from core.utils import normalize_url

# from analyzers import (
#     PASSIVE_ANALYZERS,
#     ACTIVE_SAFE_ANALYZERS,
# )

# from analyzers.sqli_error_based import analyze_url_sqli
# from analyzers.xss_reflection import analyze_url_xss

# class ScannerVulnerability:
#     def __init__(self, target_url, max_pages=20):
#         self.target_url = normalize_url(target_url)
#         self.client = HttpClient(timeout=10, verify_tls=True)
#         self.max_pages = max_pages

#     def check_liveness(self):
#         return self.client.is_live(self.target_url)

#     def scan(
#         self,
#         run_passive=True,
#         run_active_safe=True,
#         run_parameter_checks=False
#     ):
#         results = []

#         if not self.check_liveness():
#             print(f"[!] Target {self.target_url} is unreachable or offline.")
#             return results

#         base_response = self.client.get(self.target_url)
#         if not base_response:
#             return results

#         # 1) Passive
#         if run_passive:
#             for analyzer in PASSIVE_ANALYZERS:
#                 results.extend(analyzer.analyze(self.target_url, base_response, self.client))

#         # 2) Safe active
#         if run_active_safe:
#             for analyzer in ACTIVE_SAFE_ANALYZERS:
#                 results.extend(analyzer.analyze(self.target_url, base_response, self.client))

#         # 3) Parameter checks
#         if run_parameter_checks:
#             crawler = WebCrawler(self.target_url, max_pages=self.max_pages)
#             pages = crawler.crawl(self.client)

#             for url, _html in pages:
#                 results.extend(analyze_url_sqli(url, self.client))
#                 results.extend(analyze_url_xss(url, self.client))

#         unique = {}
#         for r in results:
#             key = (r.target_url, r.vulnerability, r.description)
#             unique[key] = r

#         return list(unique.values())
