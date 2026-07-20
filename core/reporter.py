import json
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader


class Reporter:

    def __init__(self, output_dir="reports"):

        self.output_dir = Path(output_dir)

        self.output_dir.mkdir(exist_ok=True)

    #
    # Endpoint Inventory
    #

    def save_json(self, inventory):

        endpoints = []

        for endpoint in inventory.all():

            endpoints.append(
                {
                    "method": endpoint.method,
                    "path": endpoint.path,
                    "content_type": endpoint.content_type,
                    "source": endpoint.source,
                }
            )

        report = {
            "summary": {
                "total_endpoints": len(endpoints),
            },
            "endpoints": endpoints,
        }

        outfile = self.output_dir / "inventory.json"

        with outfile.open("w", encoding="utf-8") as fp:

            json.dump(
                report,
                fp,
                indent=4,
            )

        return outfile

    #
    # Plugin Results
    #

    def save_plugins(self, plugin_results):

        report = {
            name: result.to_dict()
            for name, result in plugin_results.items()
        }

        outfile = self.output_dir / "plugins.json"

        with outfile.open("w", encoding="utf-8") as fp:

            json.dump(
                report,
                fp,
                indent=4,
            )

        return outfile

    #
    # HTML Report
    #

    def save_html(
        self,
        target,
        crawl_results,
        inventory,
        plugin_results,
        duration,
    ):

        env = Environment(
            loader=FileSystemLoader("templates")
        )

        template = env.get_template(
            "report.html"
        )

        endpoints = []

        for endpoint in inventory.all():

            endpoints.append(
                {
                    "method": endpoint.method,
                    "path": endpoint.path,
                    "content_type": endpoint.content_type,
                    "source": endpoint.source,
                }
            )

        plugins = {
            name: result.to_dict()
            for name, result in plugin_results.items()
        }

        total_findings = sum(
            len(result.findings)
            for result in plugin_results.values()
        )

        html = template.render(

            target=target,

            timestamp=datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

            duration=f"{duration:.2f}",

            summary={

                "pages": len(
                    crawl_results["pages"]
                ),

                "scripts": len(
                    crawl_results["scripts"]
                ),

                "endpoints": len(
                    endpoints
                ),

                "plugins": len(
                    plugin_results
                ),

                "findings": total_findings,
            },

            endpoints=endpoints,

            plugins=plugins,
        )

        outfile = (
            self.output_dir
            / "assessment.html"
        )

        outfile.write_text(
            html,
            encoding="utf-8",
        )

        return outfile
