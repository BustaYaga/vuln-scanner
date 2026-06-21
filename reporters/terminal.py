from rich.console import Console
from rich.table import Table
from rich import box
from models import ScanResult

console = Console()

def print_results(scan_result: ScanResult) -> None:
    # print header
    console.print(f"\n[bold]Target:[/bold] {scan_result.target}")
    console.print(f"[bold]Scan date:[/bold] {scan_result.scan_date}\n")

    # build table
    table = Table(box=box.ROUNDED)
    table.add_column("Port",     style="cyan")
    table.add_column("Protocol", style="white")
    table.add_column("Service",  style="green")
    table.add_column("Version",  style="white")
    table.add_column("CVEs",     style="red")
    table.add_column("Severity", style="yellow")

    for port in scan_result.open_ports:
        service = port.service_info.service_name if port.service_info else "unknown"
        version = port.service_info.version if port.service_info else "unknown"
        cve_count = str(len(port.cve_entries))
        severity = port.highest_severity if port.has_cves else "NONE"
        severity_text = f"[{severity_colour(severity)}]{severity}[/]"


        table.add_row(
            str(port.port),
            port.protocol,
            service,
            version,
            cve_count,
            severity_text
        )
        
    console.print(table)
    console.print(f"\n[bold]Open ports:[/bold] {len(scan_result.open_ports)}")
    console.print(f"[bold]Total CVEs:[/bold] {scan_result.total_cves}\n")

def severity_colour(severity: str) -> str:
    colours = {
        "CRITICAL": "bold red",
        "HIGH":     "red",
        "MEDIUM":   "yellow",
        "LOW":      "green",
        "NONE":     "white"
    }
    return colours.get(severity, "white")