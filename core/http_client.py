import requests

class HttpClient:
    def __init__(self,timeout=15):
        self.timeout = timeout
    def get(self,url,headers=None):
        try:
            response = requests.get(url=url,headers=headers,timeout=self.timeout)
            return response
        except requests.RequestException() as e:
            return e