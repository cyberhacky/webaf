from core.findings import Finding
from modules.base import AssessmentPlugin


class HeadersPlugin(AssessmentPlugin):

    name = "Headers"

    def run(self, client, inventory):

        findings = []

        response = client.get("/")

        headers = response.headers

        checks = [
            (
                "Content-Security-Policy",
                "Missing Content-Security-Policy",
                "Configure a Content-Security-Policy header.",
            ),
            (
                "X-Frame-Options",
                "Missing X-Frame-Options",
                "Set X-Frame-Options to DENY or SAMEORIGIN.",
            ),
            (
                "X-Content-Type-Options",
                "Missing X-Content-Type-Options",
                "Set X-Content-Type-Options to nosniff.",
            ),
        ]

        for header, title, recommendation in checks:

            if header not in headers:

                findings.append(
                    Finding(
                        plugin="Headers",
                        severity="Low",
                        title=title,
                        recommendation=recommendation,
                    )
                )

        return findings
