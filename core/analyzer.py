import re
from urllib.parse import urlparse

from core.client import HTTPClient
from core.endpoints import Endpoint, EndpointInventory


class JSAnalyzer:
    HTTP_METHODS = "get|post|put|delete|patch|head|options"

    def __init__(
        self,
        client: HTTPClient,
        include_inferred: bool = False,
    ):
        self.client = client
        self.include_inferred = include_inferred

    def analyze(self, scripts):
        inventory = EndpointInventory()

        for script in scripts:
            try:
                js = self.client.get(script).text
            except Exception:
                continue

            inventory.extend(self._extract_fetch(js, script))
            inventory.extend(self._extract_axios(js, script))
            inventory.extend(self._extract_xhr(js, script))
            inventory.extend(self._extract_jquery(js, script))
            inventory.extend(self._extract_generic_http(js, script))
            inventory.extend(self._extract_graphql(js, script))

            if self.include_inferred:
                inventory.extend(
                    self._extract_spa_routes(js, script)
                )
                inventory.extend(
                    self._extract_api_literals(js, script)
                )

        return self._normalize(inventory)

    def _extract_fetch(self, js, source):
        inventory = EndpointInventory()

        pattern = re.compile(
            r'fetch\s*\(\s*([\'"`])(.+?)\1'
            r'(?:\s*,\s*\{(.*?)\})?',
            re.DOTALL,
        )

        for match in pattern.finditer(js):
            options = match.group(3) or ""
            method = "GET"

            method_match = re.search(
                r'method\s*:\s*[\'"]([A-Z]+)[\'"]',
                options,
                re.I,
            )

            if method_match:
                method = method_match.group(1).upper()

            content_type = None

            if "application/xml" in options:
                content_type = "application/xml"
            elif "application/json" in options:
                content_type = "application/json"

            self._add(
                inventory,
                method,
                match.group(2),
                source,
                content_type,
            )

        return inventory

    def _extract_axios(self, js, source):
        inventory = EndpointInventory()

        pattern = re.compile(
            r'axios\.(get|post|put|delete|patch|head|options)'
            r'\s*\(\s*([\'"`])(.+?)\2',
            re.I,
        )

        for match in pattern.finditer(js):
            self._add(
                inventory,
                match.group(1).upper(),
                match.group(3),
                source,
            )

        return inventory

    def _extract_xhr(self, js, source):
        inventory = EndpointInventory()

        pattern = re.compile(
            r'\.open\s*\(\s*[\'"]([A-Z]+)[\'"]'
            r'\s*,\s*([\'"`])(.+?)\2',
            re.I,
        )

        for match in pattern.finditer(js):
            self._add(
                inventory,
                match.group(1).upper(),
                match.group(3),
                source,
            )

        return inventory

    def _extract_jquery(self, js, source):
        inventory = EndpointInventory()

        simple = re.compile(
            r'\$\.(get|post|getJSON)\s*\(\s*([\'"`])(.+?)\2',
            re.I,
        )

        for match in simple.finditer(js):
            method = "POST" if match.group(1).lower() == "post" else "GET"

            self._add(
                inventory,
                method,
                match.group(3),
                source,
            )

        ajax = re.compile(
            r'\$\.ajax\s*\(\s*\{(.*?)\}\s*\)',
            re.S | re.I,
        )

        for block in ajax.finditer(js):
            body = block.group(1)

            url = re.search(
                r'url\s*:\s*[\'"`](.+?)[\'"`]',
                body,
                re.I,
            )

            if not url:
                continue

            method = "GET"

            method_match = re.search(
                r'(?:type|method)\s*:\s*[\'"]([A-Z]+)[\'"]',
                body,
                re.I,
            )

            if method_match:
                method = method_match.group(1).upper()

            self._add(
                inventory,
                method,
                url.group(1),
                source,
            )

        return inventory

    def _extract_generic_http(self, js, source):
        inventory = EndpointInventory()

        pattern = re.compile(
            rf'(?:this\.)?(?:http|client|api|service)'
            rf'\.({self.HTTP_METHODS})'
            r'\s*\(\s*([\'"`])(.+?)\2',
            re.I,
        )

        for match in pattern.finditer(js):
            self._add(
                inventory,
                match.group(1).upper(),
                match.group(3),
                source,
            )

        return inventory

    def _extract_spa_routes(self, js, source):
        inventory = EndpointInventory()

        patterns = [
            r'path\s*:\s*([\'"`])([^\'"`]+)\1',
            r'route\s*:\s*([\'"`])([^\'"`]+)\1',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, js, re.I):
                route = match.group(2).strip()

                if not route or route == "**":
                    continue

                if not route.startswith("/"):
                    route = f"/{route}"

                self._add(
                    inventory,
                    "GET",
                    route,
                    f"{source} (SPA route)",
                )

        return inventory

    def _extract_api_literals(self, js, source):
        inventory = EndpointInventory()

        pattern = re.compile(
            r'([\'"`])'
            r'((?:https?://[^\'"`\s]+|/'
            r'(?:api|rest|graphql|oauth|auth|v[0-9]+)'
            r'[^\'"`\s]*))'
            r'\1',
            re.I,
        )

        for match in pattern.finditer(js):
            self._add(
                inventory,
                "GET",
                match.group(2),
                f"{source} (JS literal)",
            )

        return inventory

    def _extract_graphql(self, js, source):
        inventory = EndpointInventory()

        if not re.search(
            r'graphql|apollo|createHttpLink|gql',
            js,
            re.I,
        ):
            return inventory

        paths = re.findall(
            r'[\'"`]([^\'"`]*graphql[^\'"`]*)[\'"`]',
            js,
            re.I,
        )

        if not paths:
            paths = ["/graphql"]

        for path in paths:
            self._add(
                inventory,
                "POST",
                path,
                source,
                "application/json",
            )

        return inventory

    def _add(
        self,
        inventory,
        method,
        path,
        source,
        content_type=None,
    ):
        path = self._normalize_path(path)

        if not path or self._is_static_asset(path):
            return

        inventory.add(
            Endpoint(
                method=method,
                path=path,
                content_type=content_type,
                source=source,
            )
        )

    def _normalize(self, inventory):
        normalized = EndpointInventory()
        seen = set()

        for endpoint in inventory:
            endpoint.path = self._normalize_path(endpoint.path)

            key = (
                endpoint.method,
                endpoint.path,
                endpoint.content_type,
            )

            if key in seen:
                continue

            seen.add(key)
            normalized.add(endpoint)

        return normalized

    def _normalize_path(self, path):
        if not path:
            return path

        path = re.sub(r"\$\{[^}]+\}", "{param}", path)
        path = re.sub(r"\{[^}]+\}", "{param}", path)
        path = path.split("?")[0]
        path = path.split("#")[0]

        if path.startswith(("http://", "https://")):
            path = urlparse(path).path

        if not path.startswith("/"):
            path = f"/{path}"

        return re.sub(r"/+", "/", path)

    def _is_static_asset(self, path):
        return bool(
            re.search(
                r"\.(?:css|js|map|png|jpg|jpeg|gif|svg|ico|woff2?)$",
                path,
                re.I,
            )
        )
