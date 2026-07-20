from __future__ import annotations

import time
from collections.abc import Iterable
from urllib.parse import urljoin, urlparse

import requests
from requests.exceptions import RequestException


class ScopeError(ValueError):
    """Raised when a request would leave the approved scan scope."""


class ActiveScanRequiredError(PermissionError):
    """Raised when a non-passive request is attempted without --active."""


class HTTPClient:
    SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
    RETRY_STATUS_CODES = {429, 500, 502, 503, 504}

    def __init__(
        self,
        base_url: str,
        timeout: int = 10,
        rate_limit: float = 2.0,
        retries: int = 2,
        active: bool = False,
        verify_tls: bool = True,
        allowed_hosts: Iterable[str] | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ):
        parsed = urlparse(base_url)

        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(
                "Target must be a complete HTTP(S) URL."
            )

        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.retries = retries
        self.active = active
        self.verify_tls = verify_tls
        self.session = requests.Session()

        target_host = parsed.hostname

        self.allowed_hosts = {
            host.lower()
            for host in (allowed_hosts or [target_host])
            if host
        }

        if headers:
            self.session.headers.update(headers)

        if cookies:
            self.session.cookies.update(cookies)

        self._last_request_at = 0.0

    def _build_url(self, path: str) -> str:
        return urljoin(f"{self.base_url}/", path)

    def _assert_in_scope(self, url: str) -> None:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        if parsed.scheme not in {"http", "https"}:
            raise ScopeError(
                f"Unsupported URL scheme: {parsed.scheme}"
            )

        if hostname not in self.allowed_hosts:
            raise ScopeError(
                f"Blocked out-of-scope request to {hostname}."
            )

    def _wait_for_rate_limit(self) -> None:
        if self.rate_limit <= 0:
            return

        interval = 1.0 / self.rate_limit
        elapsed = time.monotonic() - self._last_request_at
        remaining = interval - elapsed

        if remaining > 0:
            time.sleep(remaining)

    def request(
        self,
        method: str,
        path: str = "/",
        **kwargs,
    ) -> requests.Response:
        method = method.upper()

        if not self.active and method not in self.SAFE_METHODS:
            raise ActiveScanRequiredError(
                f"{method} requests require --active."
            )

        url = self._build_url(path)
        self._assert_in_scope(url)

        # Redirects are not followed automatically, preventing scope bypass.
        kwargs["allow_redirects"] = False

        last_error: Exception | None = None

        for attempt in range(self.retries + 1):
            self._wait_for_rate_limit()

            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    timeout=self.timeout,
                    verify=self.verify_tls,
                    **kwargs,
                )

                self._last_request_at = time.monotonic()

            except RequestException as exc:
                last_error = exc

                if attempt == self.retries:
                    raise

                time.sleep(2**attempt)
                continue

            if (
                response.status_code not in self.RETRY_STATUS_CODES
                or attempt == self.retries
            ):
                return response

            response.close()
            time.sleep(2**attempt)

        raise last_error or RuntimeError("Request failed unexpectedly")

    def get(self, path: str = "/", **kwargs):
        return self.request("GET", path, **kwargs)

    def head(self, path: str = "/", **kwargs):
        return self.request("HEAD", path, **kwargs)

    def options(self, path: str = "/", **kwargs):
        return self.request("OPTIONS", path, **kwargs)

    def post(self, path: str, data=None, **kwargs):
        return self.request("POST", path, data=data, **kwargs)
