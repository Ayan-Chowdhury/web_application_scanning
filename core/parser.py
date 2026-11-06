from urllib.parse import urlparse


class URLParser:

    @staticmethod
    def parse(url):

        parsed=urlparse(url)

        return{

            "scheme":parsed.scheme,

            "host":parsed.netloc,

            "path":parsed.path,

            "query":parsed.query

        }