from dataclasses import dataclass
from typing import Iterator, List


@dataclass
class Endpoint:
    path: str
    method: str = "GET"
    content_type: str | None = None
    source: str | None = None


class EndpointInventory:
    def __init__(self):
        self._items: list[Endpoint] = []

    def add(self, endpoint: Endpoint):
        if not any(
            e.path == endpoint.path
            and e.method == endpoint.method
            and e.content_type == endpoint.content_type
            for e in self._items
        ):
            self._items.append(endpoint)

    def extend(self, endpoints: "EndpointInventory"):
        for endpoint in endpoints:
            self.add(endpoint)

    def __iter__(self) -> Iterator[Endpoint]:
        return iter(self._items)

    def all(self) -> List[Endpoint]:
        return sorted(
            self._items,
            key=lambda endpoint: (
                endpoint.path,
                endpoint.method,
                endpoint.content_type or "",
            ),
        )
