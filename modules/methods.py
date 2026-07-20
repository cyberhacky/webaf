from core.findings import Finding
from modules.base import AssessmentPlugin


class HTTPMethodsPlugin(AssessmentPlugin):

    name = "HTTP Methods"

    def run(self, client, inventory):

        findings = []

        try:
            response = client.request("OPTIONS", "/")
        except Exception as exc:
            return [
                Finding(
                    plugin=self.name,
                    severity="Error",
                    title="OPTIONS request failed",
                    evidence=str(exc),
                )
            ]

        allow = response.headers.get("Allow")

        if not allow:
            return findings

        methods = {
            method.strip().upper()
            for method in allow.split(",")
        }

        if "TRACE" in methods:
            findings.append(
                Finding(
                    plugin=self.name,
                    severity="High",
                    title="TRACE method enabled",
                    recommendation="Disable TRACE unless it is explicitly required.",
                    evidence=allow,
                )
            )

        if "PUT" in methods:
            findings.append(
                Finding(
                    plugin=self.name,
                    severity="Info",
                    title="PUT method enabled",
                    recommendation="Verify PUT endpoints are authenticated and intended.",
                    evidence=allow,
                )
            )

        if "DELETE" in methods:
            findings.append(
                Finding(
                    plugin=self.name,
                    severity="Info",
                    title="DELETE method enabled",
                    recommendation="Verify DELETE operations require appropriate authorization.",
                    evidence=allow,
                )
            )

        if "PATCH" in methods:
            findings.append(
                Finding(
                    plugin=self.name,
                    severity="Info",
                    title="PATCH method enabled",
                    recommendation="Review PATCH endpoints for proper authorization and input validation.",
                    evidence=allow,
                )
            )

        if "CONNECT" in methods:
            findings.append(
                Finding(
                    plugin=self.name,
                    severity="High",
                    title="CONNECT method enabled",
                    recommendation="Disable CONNECT unless proxy functionality is intentionally provided.",
                    evidence=allow,
                )
            )

        return findings
