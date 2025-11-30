import sys
import time
import socket
import ssl
import requests

import dns.resolver
import dns.exception
from urllib.parse import urlparse
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box
from typing import TypedDict, cast
from collections.abc import Iterable

class HTTPResult(TypedDict):
    status_code: int | None
    reason: str | None
    latency: str | None
    redirects: int | None
    url: str | None
    server: str | None
    error: str | None

class SSLResult(TypedDict):
    valid: bool
    expiry: str | None
    days_left: int | None
    issuer: str | None
    error: str | None

console = Console()

def get_domain_from_url(url: str) -> tuple[str, str]:
    if not url.startswith("http"):
        url = "https://" + url
    parsed = urlparse(url)
    return parsed.netloc, url

def check_dns(domain: str) -> dict[str, list[str]]:
    records: dict[str, list[str]] = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    for r_type in record_types:
        try:
            answers = resolver.resolve(domain, r_type)
            # Ensure we convert to string to avoid Any
            records[r_type] = [str(r) for r in cast(Iterable[object], answers)]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            records[r_type] = []
        except Exception as e:
             records[r_type] = [f"Error: {str(e)}"]
    return records

def check_http(url: str) -> HTTPResult:
    try:
        start_time = time.time()
        response = requests.get(url, timeout=5)
        latency = (time.time() - start_time) * 1000
        return {
            "status_code": response.status_code,
            "reason": response.reason,
            "latency": f"{latency:.2f} ms",
            "redirects": len(response.history),
            "url": str(response.url),
            "server": str(response.headers.get("Server", "Unknown")),
            "error": None
        }
    except requests.exceptions.RequestException as e:
        return {
            "status_code": None,
            "reason": None,
            "latency": None,
            "redirects": None,
            "url": None,
            "server": None,
            "error": str(e)
        }

def check_ssl(domain: str) -> SSLResult:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return {
                        "valid": False,
                        "expiry": None,
                        "days_left": None,
                        "issuer": None,
                        "error": "No certificate found"
                    }
                
                not_after = str(cert['notAfter'])
                expiry_date = datetime.strptime(not_after, r'%b %d %H:%M:%S %Y %Z')
                days_left = (expiry_date - datetime.now()).days
                
                # Handle issuer safely
                issuer_list = cert.get('issuer', [])
                issuer_dict: dict[str, str] = {}
                for item in issuer_list:
                    if item and len(item) > 0 and item[0]:
                        key, val = item[0]
                        issuer_dict[str(key)] = str(val)

                return {
                    "valid": True,
                    "expiry": expiry_date.strftime('%Y-%m-%d'),
                    "days_left": days_left,
                    "issuer": str(issuer_dict.get('organizationName', 'Unknown')),
                    "error": None 
                }
    except Exception as e:
        return {
            "valid": False,
            "expiry": None,
            "days_left": None,
            "issuer": None,
            "error": str(e)
        }

def main():
    console.clear()
    console.print(Panel.fit("[bold cyan]Web & DNS Verifier[/bold cyan]", border_style="cyan"))
    
    if len(sys.argv) > 1:
        url_input = sys.argv[1]
    else:
        url_input = Prompt.ask("[bold green]Enter URL to verify[/bold green]", default="https://www.google.com")
    
    domain, url = get_domain_from_url(url_input)
    
    console.print(f"\n[bold yellow]Analyzing:[/bold yellow] [blue]{url}[/blue] (Domain: {domain})\n")

    with console.status("[bold green]Running checks...[/bold green]", spinner="dots"):
        # Run checks
        dns_data = check_dns(domain)
        http_data = check_http(url)
        ssl_data = check_ssl(domain)
        time.sleep(0.5) # Just for effect

    # --- Display Results ---

    # 1. HTTP Status
    http_table = Table(title="HTTP Status", box=box.ROUNDED, expand=True)
    http_table.add_column("Metric", style="cyan")
    http_table.add_column("Value", style="white")

    if http_data.get("error"):
        http_table.add_row("Status", "[bold red]FAILED[/bold red]")
        http_table.add_row("Error", f"[red]{http_data['error']}[/red]")
    else:
        status_code = int(http_data['status_code']) if http_data['status_code'] is not None else 0
        status_color = "green" if 200 <= status_code < 300 else "red"
        http_table.add_row("Status Code", f"[{status_color}]{status_code} {http_data['reason']}[/{status_color}]")
        http_table.add_row("Latency", str(http_data['latency']))
        http_table.add_row("Redirects", str(http_data['redirects']))
        http_table.add_row("Final URL", str(http_data['url']))
        http_table.add_row("Server", str(http_data['server']))

    console.print(http_table)
    console.print("")

    # 2. SSL Certificate
    ssl_table = Table(title="SSL Certificate", box=box.ROUNDED, expand=True)
    ssl_table.add_column("Metric", style="magenta")
    ssl_table.add_column("Value", style="white")

    if ssl_data.get("error"):
        ssl_table.add_row("Valid", "[bold red]NO[/bold red]")
        ssl_table.add_row("Error", f"[red]{ssl_data['error']}[/red]")
    else:
        days_left = int(ssl_data['days_left']) if ssl_data['days_left'] is not None else 0
        days_color = "green" if days_left > 30 else "yellow" if days_left > 7 else "red"
        ssl_table.add_row("Valid", "[bold green]YES[/bold green]")
        ssl_table.add_row("Expiry Date", str(ssl_data['expiry']))
        ssl_table.add_row("Days Remaining", f"[{days_color}]{days_left} days[/{days_color}]")
        ssl_table.add_row("Issuer", str(ssl_data['issuer']))

    console.print(ssl_table)
    console.print("")

    # 3. DNS Records
    dns_table = Table(title=f"DNS Records for {domain}", box=box.ROUNDED, expand=True)
    dns_table.add_column("Type", style="yellow", width=10)
    dns_table.add_column("Value", style="white")

    for r_type, values in dns_data.items():
        if not values:
            dns_table.add_row(r_type, "[dim]No records found[/dim]")
        else:
            for i, val in enumerate(values):
                dns_table.add_row(str(r_type) if i == 0 else "", str(val))
            dns_table.add_row("", "") # Spacer

    console.print(dns_table)
    
    console.print(Panel("[bold green]Verification Complete![/bold green]", border_style="green"))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Aborted by user.[/bold red]")
