from __future__ import annotations

from collections import deque
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from core.client import HTTPClient


class Crawler:
    def __init__(
        self,
        client: HTTPClient,
        max_pages: int = 100,
        max_depth: int = 2,
    ):
        self.client = client
        self.max_pages = max_pages
        self.max_depth = max_depth

    def _extract(self, html: str):
        soup = BeautifulSoup(html, "html.parser")

        pages = set()
        scripts = set()

        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()

            if not href or href.startswith("#"):
                continue

            parsed = urlparse(href)

            if parsed.scheme in {"mailto", "javascript", "tel", "data"}:
                continue

            absolute_url = urljoin(f"{self.client.base_url}/", href)

            try:
                self.client._assert_in_scope(absolute_url)
            except Exception:
                continue

            path = urlparse(absolute_url).path or "/"
            pages.add(path)

        for tag in soup.find_all("script", src=True):
            src = tag["src"].strip()

            if not src:
                continue

            absolute_url = urljoin(f"{self.client.base_url}/", src)

            try:
                self.client._assert_in_scope(absolute_url)
            except Exception:
                continue

            path = urlparse(absolute_url).path

            if path:
                scripts.add(path)

        return pages, scripts

    def crawl(self, start: str = "/"):
        visited = set()
        queue = deque([(start, 0)])

        pages = set()
        scripts = set()

        while queue and len(visited) < self.max_pages:
            path, depth = queue.popleft()

            if path in visited:
                continue

            visited.add(path)

            try:
                response = self.client.get(path)
            except Exception:
                continue

            if response.status_code >= 400:
                continue

            content_type = response.headers.get("Content-Type", "").lower()

            if "text/html" not in content_type:
                continue

            pages.add(path)

            found_pages, found_scripts = self._extract(response.text)
            scripts.update(found_scripts)

            if depth >= self.max_depth:
                continue

            for page in sorted(found_pages):
                if page not in visited:
                    queue.append((page, depth + 1))

        return {
            "pages": sorted(pages),
            "scripts": sorted(scripts),
        }
