from core.http_client import HttpClient
from analyzers.headers import analyze_headers

class Scanner_Vulnerability:
    def __init__(self, target_url):
        self.target_url = target_url
        self.client = HttpClient()

    def scan(self):
        response = self.client.get(self.target_url)
        if not response:
            return []

        results = []
        results.extend(analyze_headers(response))
        return results
