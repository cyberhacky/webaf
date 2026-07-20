from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone


@dataclass
class Finding:
    plugin: str
    severity: str
    title: str

    endpoint: str | None = None
    url: str | None = None

    recommendation: str | None = None
    evidence: str | None = None

    timestamp: str | None = None

    def __post_init__(self):

        if self.timestamp is None:

            self.timestamp = (
                datetime.now(timezone.utc)
                .replace(microsecond=0)
                .isoformat()
            )

    def to_dict(self) -> dict:

        return asdict(self)
