import importlib
import inspect
import pkgutil
import time

from core.findings import Finding
from core.results import PluginResult
from modules.base import AssessmentPlugin


class PluginManager:

    def __init__(self):

        self.plugins = []

        self._discover_plugins()

    def _discover_plugins(self):

        import modules

        for _, module_name, _ in pkgutil.iter_modules(modules.__path__):

            if module_name == "base":
                continue

            module = importlib.import_module(
                f"modules.{module_name}"
            )

            for _, obj in inspect.getmembers(
                module,
                inspect.isclass,
            ):

                if (
                    issubclass(obj, AssessmentPlugin)
                    and obj is not AssessmentPlugin
                ):
                    self.plugins.append(obj())

    def _normalize_findings(self, plugin, findings):

        normalized = []

        if findings is None:
            return normalized

        for finding in findings:

            if isinstance(finding, Finding):

                normalized.append(finding)

            elif isinstance(finding, dict):

                normalized.append(
                    Finding(
                        plugin=finding.get("plugin", plugin.name),
                        severity=finding.get("severity", "Info"),
                        title=finding.get("title", "Finding"),
                        endpoint=finding.get("endpoint"),
                        url=finding.get("url"),
                        recommendation=finding.get("recommendation"),
                        evidence=finding.get("evidence"),
                        timestamp=finding.get("timestamp"),
                    )
                )

            else:

                normalized.append(
                    Finding(
                        plugin=plugin.name,
                        severity="Error",
                        title="Unsupported finding type",
                        evidence=repr(finding),
                    )
                )

        return normalized

    def run(self, client, inventory):

        results = {}

        for plugin in self.plugins:

            start = time.perf_counter()

            try:

                findings = self._normalize_findings(
                    plugin,
                    plugin.run(client, inventory),
                )

            except Exception as exc:

                findings = [
                    Finding(
                        plugin=plugin.name,
                        severity="Error",
                        title="Plugin execution failed",
                        evidence=str(exc),
                    )
                ]

            duration = round(
                time.perf_counter() - start,
                4,
            )

            results[plugin.name] = PluginResult(
                name=plugin.name,
                duration=duration,
                findings=findings,
            )

        return results
