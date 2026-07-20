from core.findings import Finding
from modules.base import AssessmentPlugin


class XXEPlugin(AssessmentPlugin):

    name = "XXE"

    def run(self, client, inventory):

        findings = []

        for endpoint in inventory.all():

            if endpoint.content_type and "xml" in endpoint.content_type.lower():

                findings.append(
                    Finding(
                        plugin="XXE",
                        severity="Info",
                        title="XML endpoint discovered",
                        endpoint=endpoint.path,
                        recommendation=(
                            "Review XML parser configuration and "
                            "disable external entity resolution if not required."
                        ),
                    )
                )

        return findings
