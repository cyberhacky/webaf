from core.findings import Finding
from modules.base import AssessmentPlugin


class SwaggerPlugin(AssessmentPlugin):

    name = "Swagger/OpenAPI"

    PATHS = (
        "/swagger",
        "/swagger/",
        "/swagger/index.html",
        "/swagger-ui",
        "/swagger-ui/",
        "/swagger-ui.html",
        "/swagger.json",
        "/swagger.yaml",
        "/swagger.yml",
        "/openapi.json",
        "/openapi.yaml",
        "/openapi.yml",
        "/api-docs",
        "/v2/api-docs",
        "/v3/api-docs",
    )

    def run(self, client, inventory):

        findings = []

        for path in self.PATHS:

            try:

                response = client.get(
                    path,
                    allow_redirects=True,
                )

            except Exception:

                continue

            if response.status_code != 200:

                continue

            content_type = (
                response.headers.get(
                    "Content-Type",
                    ""
                ).lower()
            )

            body = response.text.lower()

            #
            # Swagger UI
            #

            if (
                "swagger-ui" in body
                or "swagger ui" in body
            ):

                findings.append(
                    Finding(
                        plugin=self.name,
                        severity="Info",
                        title="Swagger UI exposed",
                        endpoint=path,
                        url=client.base_url + path,
                        recommendation=(
                            "Restrict public access to API documentation."
                        ),
                    )
                )

                continue

            #
            # OpenAPI JSON/YAML
            #

            if (
                "openapi" in body
                or '"swagger"' in body
                or "application/vnd.oai.openapi" in content_type
                or "application/json" in content_type
                or "yaml" in content_type
            ):

                findings.append(
                    Finding(
                        plugin=self.name,
                        severity="Info",
                        title="OpenAPI specification exposed",
                        endpoint=path,
                        url=client.base_url + path,
                        recommendation=(
                            "Restrict access to API specifications if they are not intended to be public."
                        ),
                    )
                )

        return findings
