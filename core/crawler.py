from bs4 import BeautifulSoup
from urllib.parse import urljoin

class web_crawler:
    def __init__(self,base_url):
        self.base_url = base_url
        self.visited = set()

    def extract_links(selfself,html):
        soup = BeautifulSoup(html,'html.parser')
        links = set()

        for tag in soup.find_all('a', href=True):
            link=urljoin(self.base_url,tag['href'])
            if self.base_url in link:
                links.add(link)
        return links