import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class HttpClient:
    def __init__(self, timeout=10, verify_tls=False, user_agent=None):
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        })

    def get(self, url, headers=None, allow_redirects=True):
        try:
            return self.session.get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                verify=self.verify_tls
            )
        except requests.exceptions.SSLError:
            # Fallback to disabling SSL verification if TLS validation fails
            try:
                return self.session.get(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=allow_redirects,
                    verify=False
                )
            except requests.RequestException:
                return None
        except requests.RequestException:
            return None

    def head(self, url, headers=None, allow_redirects=True):
        try:
            return self.session.head(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                verify=self.verify_tls
            )
        except requests.exceptions.SSLError:
            try:
                return self.session.head(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=allow_redirects,
                    verify=False
                )
            except requests.RequestException:
                return None
        except requests.RequestException:
            return None

    def is_live(self, url):
        """Check if target web server is reachable."""
        res = self.get(url)
        return res is not None and res.status_code < 500

