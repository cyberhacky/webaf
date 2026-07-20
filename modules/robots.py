from core.findings import Finding
from modules.base import AssessmentPlugin


class RobotsPlugin(AssessmentPlugin):

    name = "Robots"

    def run(self, client, inventory):

        findings = []

        try:
            response = client.get("/robots.txt")
        except Exception:
            return findings

        if response.status_code != 200:
            return findings

        findings.append(
            Finding(
                plugin=self.name,
                severity="Info",
                title="robots.txt exposed",
                endpoint="/robots.txt",
                url=f"{client.base_url}/robots.txt",
                recommendation="Review robots.txt to ensure sensitive paths are not disclosed.",
            )
        )

        interesting = (
            "admin",
            "login",
            "api",
            "backup",
            "private",
            "secret",
            "config",
            "test",
            "dev",
        )

        for line in response.text.splitlines():

            line = line.strip()

            if not line or line.startswith("#"):
                continue

            lower = line.lower()

            if lower.startswith("disallow:"):

                path = line.split(":", 1)[1].strip()

                severity = (
                    "Low"
                    if any(keyword in path.lower() for keyword in interesting)
                    else "Info"
                )

                findings.append(
                    Finding(
                        plugin=self.name,
                        severity=severity,
                        title="Disallowed path",
                        endpoint=path,
                        evidence=line,
                    )
                )

            elif lower.startswith("sitemap:"):

                sitemap = line.split(":", 1)[1].strip()

                findings.append(
                    Finding(
                        plugin=self.name,
                        severity="Info",
                        title="Sitemap discovered",
                        endpoint=sitemap,
                        evidence=line,
                    )
                )

        return findings
