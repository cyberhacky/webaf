#!/usr/bin/env python3

import argparse
import json
import os
import time
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table

from core.analyzer import JSAnalyzer
from core.browser import BrowserCrawler
from core.client import HTTPClient
from core.crawler import Crawler
from core.plugins import PluginManager
from core.reporter import Reporter

FRAMEWORK = "WebAF"
VERSION = "0.7.0"

console = Console()


def banner():
    console.rule(f"[bold cyan]{FRAMEWORK} v{VERSION}")


def build_assets_table(results):
    table = Table(title="Discovered Assets")
    table.add_column("Type", style="cyan")
    table.add_column("Path", style="green")

    for page in sorted(results["pages"]):
        table.add_row("Page", page)

    for script in sorted(results["scripts"]):
        table.add_row("Script", script)

    return table


def build_endpoint_table(inventory):
    table = Table(title="Endpoint Inventory")

    table.add_column("Method", style="cyan")
    table.add_column("Endpoint", style="green")
    table.add_column("Content-Type")
    table.add_column("Source")

    for endpoint in inventory.all():
        table.add_row(
            endpoint.method,
            endpoint.path,
            endpoint.content_type or "-",
            endpoint.source or "-",
        )

    return table


def display_plugin_results(plugin_results):
    for plugin_name, result in plugin_results.items():
        table = Table(
            title=f"{plugin_name} ({result.duration:.4f}s)"
        )

        table.add_column("Severity", style="cyan")
        table.add_column("Finding")
        table.add_column("Endpoint")

        if not result.findings:
            table.add_row("-", "No Findings", "-")
        else:
            for finding in result.findings:
                table.add_row(
                    finding.severity,
                    finding.title,
                    finding.endpoint or "-",
                )

        console.print(table)


def display_summary(
    target,
    crawl_results,
    inventory,
    plugin_results,
    duration,
):
    console.rule("[bold green]Assessment Summary")

    findings = sum(
        len(result.findings)
        for result in plugin_results.values()
    )

    table = Table(show_header=False)

    table.add_column(style="cyan")
    table.add_column()

    table.add_row("Framework", f"{FRAMEWORK} {VERSION}")
    table.add_row("Target", target)
    table.add_row("Pages", str(len(crawl_results["pages"])))
    table.add_row("JavaScript", str(len(crawl_results["scripts"])))
    table.add_row("Endpoints", str(len(inventory.all())))
    table.add_row("Plugins", str(len(plugin_results)))
    table.add_row("Findings", str(findings))
    table.add_row("Duration", f"{duration:.2f}s")

    console.print(table)


def load_json_object(path, option_name, parser):
    try:
        with open(path, "r", encoding="utf-8") as file:
            data = json.load(file)

    except (OSError, json.JSONDecodeError) as exc:
        parser.error(f"Invalid {option_name}: {exc}")

    if not isinstance(data, dict):
        parser.error(
            f"{option_name} must contain a JSON object."
        )

    return {
        str(key): str(value)
        for key, value in data.items()
    }


def main():
    parser = argparse.ArgumentParser(
        prog="webaf",
        description="WebAF - Web Application Assessment Framework",
    )

    parser.add_argument(
        "target",
        help="Target base URL, for example https://example.com",
    )

    parser.add_argument(
        "--active",
        action="store_true",
        help=(
            "Allow state-changing HTTP requests. "
            "Default: passive mode."
        ),
    )

    parser.add_argument(
        "--rate-limit",
        type=float,
        default=2.0,
        help="Maximum requests per second. Default: 2.0.",
    )

    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Retries for temporary network/server failures. Default: 2.",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP timeout in seconds. Default: 10.",
    )

    parser.add_argument(
        "--max-pages",
        type=int,
        default=100,
        help="Maximum number of pages to crawl. Default: 100.",
    )

    parser.add_argument(
        "--max-depth",
        type=int,
        default=2,
        help="Maximum crawl depth. Default: 2.",
    )

    parser.add_argument(
        "--allow-host",
        action="append",
        default=[],
        help=(
            "Additional approved hostname. "
            "May be supplied more than once."
        ),
    )

    parser.add_argument(
        "--insecure",
        action="store_true",
        help=(
            "Disable TLS certificate validation. "
            "Use only for approved test systems."
        ),
    )

    parser.add_argument(
        "--bearer-token-env",
        help=(
            "Environment variable containing a Bearer token. "
            "The token is never printed or saved in reports."
        ),
    )

    parser.add_argument(
        "--headers-file",
        help=(
            "JSON file containing additional request headers. "
            "Do not commit this file."
        ),
    )

    parser.add_argument(
        "--cookies-file",
        help=(
            "JSON file containing session cookies. "
            "Do not commit this file."
        ),
    )

    parser.add_argument(
        "--include-inferred",
        action="store_true",
        help=(
            "Include inferred SPA routes and API-style strings "
            "from JavaScript."
        ),
    )

    parser.add_argument(
        "--browser",
        action="store_true",
        help=(
            "Use a headless browser to capture runtime XHR/fetch "
            "requests. Use only on authorized targets."
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"{FRAMEWORK} {VERSION}",
    )

    args = parser.parse_args()

    if args.rate_limit < 0:
        parser.error("--rate-limit must be zero or greater.")

    if args.retries < 0:
        parser.error("--retries must be zero or greater.")

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero.")

    if args.max_pages <= 0:
        parser.error("--max-pages must be greater than zero.")

    if args.max_depth < 0:
        parser.error("--max-depth must be zero or greater.")

    parsed_target = urlparse(args.target)

    if parsed_target.scheme not in {"http", "https"}:
        parser.error("Target must begin with http:// or https://")

    if not parsed_target.hostname:
        parser.error("Target must include a hostname.")

    auth_headers = {}
    auth_cookies = {}

    if args.bearer_token_env:
        token = os.environ.get(args.bearer_token_env)

        if not token:
            parser.error(
                f"Environment variable "
                f"{args.bearer_token_env} is not set."
            )

        auth_headers["Authorization"] = f"Bearer {token}"

    if args.headers_file:
        auth_headers.update(
            load_json_object(
                args.headers_file,
                "--headers-file",
                parser,
            )
        )

    if args.cookies_file:
        auth_cookies.update(
            load_json_object(
                args.cookies_file,
                "--cookies-file",
                parser,
            )
        )

    allowed_hosts = [
        parsed_target.hostname,
        *args.allow_host,
    ]

    banner()

    mode = "ACTIVE" if args.active else "PASSIVE"
    auth_enabled = bool(auth_headers or auth_cookies)

    console.print(
        f"[yellow]Scan mode:[/yellow] {mode} | "
        f"Rate limit: {args.rate_limit} req/s | "
        f"Max pages: {args.max_pages} | "
        f"Max depth: {args.max_depth} | "
        f"Authentication: {'enabled' if auth_enabled else 'disabled'}"
    )

    if args.active:
        console.print(
            "[bold yellow]Active mode enabled. "
            "Use only on authorized targets.[/bold yellow]"
        )

    start = time.perf_counter()

    client = HTTPClient(
        args.target,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        retries=args.retries,
        active=args.active,
        verify_tls=not args.insecure,
        allowed_hosts=allowed_hosts,
        headers=auth_headers or None,
        cookies=auth_cookies or None,
    )

    crawler = Crawler(
        client,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
    )

    try:
        response = client.get("/")

    except Exception as exc:
        console.print(
            f"[bold red]Connection failed:[/bold red] {exc}"
        )
        return

    console.print(
        f"[green]Connected[/green] ({response.status_code})"
    )

    crawl_results = crawler.crawl("/")

    console.print(
        build_assets_table(crawl_results)
    )

    console.rule("[bold green]Endpoint Analysis")

    analyzer = JSAnalyzer(
        client,
        include_inferred=args.include_inferred,
    )

    inventory = analyzer.analyze(
        crawl_results["scripts"]
    )

    if args.browser:
        console.rule("[bold green]Browser Runtime Discovery")

        browser_crawler = BrowserCrawler(client)

        try:
            runtime_inventory = browser_crawler.capture("/")
            inventory.extend(runtime_inventory)

            console.print(
                f"[green]Runtime endpoints discovered:[/green] "
                f"{len(runtime_inventory.all())}"
            )

        except RuntimeError as exc:
            console.print(
                f"[bold red]Browser discovery unavailable:[/bold red] "
                f"{exc}"
            )

    console.print(
        build_endpoint_table(inventory)
    )

    console.rule("[bold magenta]Plugin Results")

    manager = PluginManager()

    plugin_results = manager.run(
        client,
        inventory,
    )

    display_plugin_results(plugin_results)

    duration = time.perf_counter() - start

    reporter = Reporter()

    inventory_json = reporter.save_json(inventory)

    plugins_json = reporter.save_plugins(
        plugin_results
    )

    html_report = reporter.save_html(
        target=args.target,
        crawl_results=crawl_results,
        inventory=inventory,
        plugin_results=plugin_results,
        duration=duration,
    )

    console.rule("[bold blue]Reports")

    console.print(
        f"[green]Inventory[/green] : {inventory_json}"
    )

    console.print(
        f"[green]Plugins[/green]   : {plugins_json}"
    )

    console.print(
        f"[green]HTML[/green]      : {html_report}"
    )

    display_summary(
        args.target,
        crawl_results,
        inventory,
        plugin_results,
        duration,
    )

    console.rule("[bold cyan]Scan Complete")


if __name__ == "__main__":
    main()
