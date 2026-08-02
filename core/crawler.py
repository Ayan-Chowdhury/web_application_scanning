from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class WebCrawler:
    def __init__(self, base_url, max_pages=30):
        self.base_url = base_url.rstrip("/")
        self.max_pages = max_pages
        self.visited = set()

        self.base_domain = urlparse(self.base_url).netloc

    def extract_links(self, html, current_url):
        soup = BeautifulSoup(html, "html.parser")
        links = set()

        for tag in soup.find_all("a", href=True):
            link = urljoin(current_url, tag["href"])
            parsed = urlparse(link)

            if parsed.netloc == self.base_domain:
                clean = link.split("#")[0].rstrip("/")
                links.add(clean)

        return links

    def crawl(self, client):
        queue = [self.base_url]
        pages = []

        while queue and len(pages) < self.max_pages:
            url = queue.pop(0)
            if url in self.visited:
                continue

            self.visited.add(url)

            resp = client.get(url)
            if not resp or resp.status_code >= 400:
                continue

            pages.append((url, resp.text))

            new_links = self.extract_links(resp.text, url)
            for link in new_links:
                if link not in self.visited and link not in queue:
                    queue.append(link)

        return pages