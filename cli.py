import argparse
from rich.console import Console
# from rich.table import console
import config
from models import ScanResult
from scanner.port_scanner import scan_port, parse_ports
from scanner.service_detector import detect_service
from scanner.cve_mapper import map_cves
from scanner.cache import init_cache
from reporters.terminal import print_results
from scanner.web_fingerprinter import fingerprint_web


parser = argparse.ArgumentParser(description="Vuln-Scanner v0.1 (Under development) ~ BustaYaga ")

parser.add_argument("target", help="IP address or hostname to scan")
parser.add_argument("--ports",   "-p", help="Ports e.g. 80,443 or 1-1024")
parser.add_argument("--profile", "-P", choices=["quick","web","ad","common","full"])
parser.add_argument("--timeout", "-t", type=float)
parser.add_argument("--threads", "-T", type=int)
parser.add_argument("--output",  "-o", choices=["json","html","csv"])
parser.add_argument("--debug", "-d", action="store_true", help="Enable debug output")
parser.add_argument("--web", "-w", action="store_true", help="Enable web application fingerprinting on HTTP/HTTPS ports")

def main():
    args = parser.parse_args()

    # determine ports to scan
    if args.profile:
        port_string = config.PORT_PROFILES[args.profile]
    elif args.ports:
        port_string = args.ports
    else:
        port_string = ",".join(str(p) for p in config.DEFAULT_PORTS)

    ports_to_scan = parse_ports(port_string)

    # perform scan
    scan_result = ScanResult(target=args.target)
    console = Console()
    console.print(r"""██╗   ██╗██╗   ██╗██╗     ███╗   ██╗      ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██║   ██║██║   ██║██║     ████╗  ██║      ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════╝╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║      ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝      ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
                                                                                                      """, style="green")
    
    console.print(f"\n[bold green]Targert: {args.target} - Scanning {len(ports_to_scan)} ports...[/bold green]\n")
    console.print(f"[green]Timeout: {args.timeout or config.TIMEOUT}s | Threads: {args.threads or config.THREAD_COUNT}[/green]\n") #Show that scan started
    debug = args.debug or config.DEBUGGING

    for port in ports_to_scan:
        result = scan_port(args.target, port, timeout=args.timeout or config.TIMEOUT)
        if result:
            result.service_info = detect_service(
                args.target, port,
                timeout=args.timeout or config.TIMEOUT,
                debug=debug
            )
            if result.service_info:
                result.cve_entries = map_cves(result.service_info)
        
            # web fingerprinting — only on HTTP ports if --web flag set
            if args.web and port in (config.HTTP_PORTS | config.HTTPS_PORTS):
                result.web_fingerprint = fingerprint_web(
                    args.target, port,
                    timeout=args.timeout or config.TIMEOUT
                )
                # map CVEs for the web app too
                if result.web_fingerprint and result.web_fingerprint.version:
                    # build a temporary ServiceInfo to reuse map_cves
                    from models import ServiceInfo
                    web_service = ServiceInfo(
                        service_name=result.web_fingerprint.app_name,
                        version=result.web_fingerprint.version
                    )
                    result.web_fingerprint.cves = map_cves(web_service)

            scan_result.port_results.append(result)
    print_results(scan_result)
    
    
if __name__ == "__main__":
    init_cache()
    main()