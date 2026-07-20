from __future__ import annotations

from dataclasses import asdict, dataclass

from core.findings import Finding


@dataclass
class PluginResult:

    name: str

    duration: float

    findings: list[Finding | dict]

    def to_dict(self):

        output = []

        for finding in self.findings:

            if hasattr(finding, "to_dict"):

                output.append(
                    finding.to_dict()
                )

            else:

                output.append(finding)

        return {
            "name": self.name,
            "duration": self.duration,
            "findings": output,
        }
