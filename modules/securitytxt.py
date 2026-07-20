from datetime import datetime, timezone

from core.findings import Finding
from modules.base import AssessmentPlugin


class SecurityTxtPlugin(AssessmentPlugin):

    name = "Security.txt"

    PATHS = (
        "/.well-known/security.txt",
        "/security.txt",
    )

    def run(self, client, inventory):

        findings = []

        response = None
        endpoint = None

        #
        # Locate security.txt
        #

        for path in self.PATHS:

            try:
                r = client.get(path)
            except Exception:
                continue

            if r.status_code == 200:

                response = r
                endpoint = path
                break

        if response is None:
            return findings

        findings.append(
            Finding(
                plugin=self.name,
                severity="Info",
                title="security.txt discovered",
                endpoint=endpoint,
                url=f"{client.base_url}{endpoint}",
            )
        )

        fields = {}

        for line in response.text.splitlines():

            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if ":" not in line:
                continue

            key, value = line.split(":", 1)

            fields.setdefault(
                key.strip().lower(),
                []
            ).append(
                value.strip()
            )

        #
        # Contact
        #

        if "contact" not in fields:

            findings.append(
                Finding(
                    plugin=self.name,
                    severity="Low",
                    title="Missing Contact field",
                    endpoint=endpoint,
                )
            )

        #
        # Policy
        #

        if "policy" not in fields:

            findings.append(
                Finding(
                    plugin=self.name,
                    severity="Info",
                    title="Missing Policy field",
                    endpoint=endpoint,
                )
            )

        #
        # Expires
        #

        if "expires" in fields:

            try:

                expires = datetime.fromisoformat(
                    fields["expires"][0].replace(
                        "Z",
                        "+00:00",
                    )
                )

                if expires < datetime.now(timezone.utc):

                    findings.append(
                        Finding(
                            plugin=self.name,
                            severity="Medium",
                            title="security.txt expired",
                            endpoint=endpoint,
                            evidence=fields["expires"][0],
                        )
                    )

            except Exception:

                findings.append(
                    Finding(
                        plugin=self.name,
                        severity="Low",
                        title="Invalid Expires field",
                        endpoint=endpoint,
                        evidence=fields["expires"][0],
                    )
                )

        else:

            findings.append(
                Finding(
                    plugin=self.name,
                    severity="Low",
                    title="Missing Expires field",
                    endpoint=endpoint,
                )
            )

        return findings
