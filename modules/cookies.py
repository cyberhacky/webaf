from http.cookies import SimpleCookie

from core.findings import Finding
from modules.base import AssessmentPlugin


class CookiesPlugin(AssessmentPlugin):

    name = "Cookies"

    def run(self, client, inventory):

        findings = []

        response = client.get("/")

        #
        # Collect all Set-Cookie headers
        #
        try:
            cookie_headers = response.raw.headers.get_all("Set-Cookie")
        except AttributeError:
            header = response.headers.get("Set-Cookie")
            cookie_headers = [header] if header else []

        for header in cookie_headers:

            cookie = SimpleCookie()

            try:
                cookie.load(header)
            except Exception:
                continue

            for name, morsel in cookie.items():

                lower = header.lower()

                if "httponly" not in lower:

                    findings.append(
                        Finding(
                            plugin="Cookies",
                            severity="Low",
                            title=f'Cookie "{name}" missing HttpOnly',
                            recommendation="Mark session cookies as HttpOnly.",
                            evidence=header,
                        )
                    )

                if "secure" not in lower:

                    findings.append(
                        Finding(
                            plugin="Cookies",
                            severity="Low",
                            title=f'Cookie "{name}" missing Secure',
                            recommendation="Transmit cookies only over HTTPS using the Secure attribute.",
                            evidence=header,
                        )
                    )

                if "samesite" not in lower:

                    findings.append(
                        Finding(
                            plugin="Cookies",
                            severity="Info",
                            title=f'Cookie "{name}" missing SameSite',
                            recommendation="Consider SameSite=Lax or SameSite=Strict.",
                            evidence=header,
                        )
                    )

        return findings
