from core.findings import Finding
from modules.base import AssessmentPlugin


class CORSPlugin(AssessmentPlugin):

    name = "CORS"

    TEST_ORIGIN = "https://webaf.invalid"

    def run(self, client, inventory):

        findings = []

        response = client.get(
            "/",
            headers={
                "Origin": self.TEST_ORIGIN
            }
        )

        acao = response.headers.get(
            "Access-Control-Allow-Origin"
        )

        acac = response.headers.get(
            "Access-Control-Allow-Credentials"
        )

        vary = response.headers.get("Vary")

        #
        # No CORS
        #

        if acao is None:

            return findings

        #
        # Wildcard
        #

        if acao == "*":

            findings.append(
                Finding(
                    plugin="CORS",
                    severity="Low",
                    title="Wildcard Access-Control-Allow-Origin",
                    recommendation=(
                        "Restrict allowed origins instead of using '*'."
                    ),
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                )
            )

        #
        # Reflection
        #

        if acao == self.TEST_ORIGIN:

            findings.append(
                Finding(
                    plugin="CORS",
                    severity="High",
                    title="Origin reflection detected",
                    recommendation=(
                        "Validate the Origin header against an allowlist."
                    ),
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                )
            )

        #
        # Credentials + wildcard
        #

        if acao == "*" and acac and acac.lower() == "true":

            findings.append(
                Finding(
                    plugin="CORS",
                    severity="High",
                    title="Wildcard origin with credentials",
                    recommendation=(
                        "Never combine wildcard origins with credentialed CORS."
                    ),
                    evidence=(
                        f"Access-Control-Allow-Origin: {acao}, "
                        f"Access-Control-Allow-Credentials: {acac}"
                    ),
                )
            )

        #
        # Missing Vary
        #

        if acao != "*" and vary != "Origin":

            findings.append(
                Finding(
                    plugin="CORS",
                    severity="Info",
                    title="Missing 'Vary: Origin' header",
                    recommendation=(
                        "Include 'Vary: Origin' when responses depend on the Origin header."
                    ),
                )
            )

        return findings
