from __future__ import annotations

import time
from urllib.parse import urljoin, urlparse

from core.client import HTTPClient
from core.endpoints import Endpoint, EndpointInventory


class BrowserCrawler:
    def __init__(
        self,
        client: HTTPClient,
        wait_ms: int = 5000,
    ):
        self.client = client
        self.wait_ms = wait_ms
        self._last_request_at = 0.0

    def _wait_for_rate_limit(self):
        if self.client.rate_limit <= 0:
            return

        interval = 1.0 / self.client.rate_limit
        elapsed = time.monotonic() - self._last_request_at
        remaining = interval - elapsed

        if remaining > 0:
            time.sleep(remaining)

        self._last_request_at = time.monotonic()

    def capture(self, start: str = "/") -> EndpointInventory:
        try:
            from playwright.sync_api import (
                Error as PlaywrightError,
                TimeoutError as PlaywrightTimeoutError,
                sync_playwright,
            )
        except ImportError as exc:
            raise RuntimeError(
                "Browser mode requires Playwright. Run: "
                "python -m pip install -r requirements.txt && "
                "python -m playwright install chromium"
            ) from exc

        inventory = EndpointInventory()
        target_url = urljoin(f"{self.client.base_url}/", start)

        def is_in_scope(url: str) -> bool:
            try:
                self.client._assert_in_scope(url)
                return True
            except Exception:
                return False

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)

            context = browser.new_context(
                extra_http_headers=dict(self.client.session.headers),
                ignore_https_errors=not self.client.verify_tls,
            )

            cookies = []

            for cookie in self.client.session.cookies:
                cookies.append(
                    {
                        "name": cookie.name,
                        "value": cookie.value,
                        "url": self.client.base_url,
                    }
                )

            if cookies:
                context.add_cookies(cookies)

            page = context.new_page()

            def handle_route(route):
                request = route.request

                if not is_in_scope(request.url):
                    route.abort()
                    return

                if (
                    not self.client.active
                    and request.method.upper()
                    not in self.client.SAFE_METHODS
                ):
                    route.abort()
                    return

                self._wait_for_rate_limit()
                route.continue_()

            def record_request(request):
                if request.resource_type not in {"fetch", "xhr"}:
                    return

                if not is_in_scope(request.url):
                    return

                parsed = urlparse(request.url)
                path = parsed.path or "/"

                inventory.add(
                    Endpoint(
                        method=request.method.upper(),
                        path=path,
                        source="browser runtime",
                    )
                )

            page.route("**/*", handle_route)
            page.on("request", record_request)

            try:
                page.goto(
                    target_url,
                    wait_until="commit",
                    timeout=max(
                        self.client.timeout * 1000,
                        30_000,
                    ),
                )

                page.wait_for_timeout(self.wait_ms)

            except PlaywrightTimeoutError:
                # The page started loading. Preserve any runtime requests
                # already observed instead of failing the full scan.
                pass

            except PlaywrightError as exc:
                raise RuntimeError(
                    f"Browser navigation failed: {exc}"
                ) from exc

            finally:
                context.close()
                browser.close()

        return inventory
