import socket
from rich.console import Console
import config
import re
import ssl
from models import ServiceInfo

console = Console()
def grab_banner(host: str, port: int, timeout: float) -> str | None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            banner = s.recv(1024)        # read up to 1024 bytes
            return banner.decode("utf-8", errors="ignore").strip()
        except:
            return None
        
def probe_http(host: str, port: int, timeout: float) -> str | None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            for path in config.PROBE_PATHS: #loop updated to try multiple paths for HTTP probing
                request = f"HEAD {path} HTTP/1.0\r\nHost: {host}\r\n\r\n"
                s.sendall(request.encode())
                response = s.recv(2048).decode("utf-8", errors="ignore")
                if "Server:" in response:
                    return response
        except:
            return None
                
def probe_https(host: str, port: int, timeout: float) -> str | None:
    context = ssl.create_default_context()
    context.check_hostname = False       # we're scanning IPs, not hostnames
    context.verify_mode = ssl.CERT_NONE  # don't validate the certificate

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
        raw.settimeout(timeout)
        try:
            with context.wrap_socket(raw, server_hostname=host) as s:
                s.connect((host, port))
                request = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n"
                s.sendall(request.encode())
                response = s.recv(2048).decode("utf-8", errors="ignore")
                return response
        except:
            return None
                        
def detect_service(host: str, port: int, timeout: float, debug: bool = False) -> ServiceInfo | None:
    debug = debug or config.DEBUGGING

    if port in config.HTTPS_PORTS:
        response = probe_https(host, port, timeout)
    elif port in config.HTTP_PORTS:
        response = probe_http(host, port, timeout)
    else:
        response = None
    #debug mode results.        
    if debug:
        if response:
            console.print(f"[dim][DEBUG] Port {port} raw response:\n{response[:500]}[/dim]")
        else:
            console.print(f"[dim][DEBUG] Port {port} — no response received[/dim]")
            
    if response:
        for pattern, service_name in config.BANNER_PATTERNS:
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                try:
                    version = match.group(1).strip()
                except IndexError:
                    version = ""
                return ServiceInfo(service_name=service_name, version=version)
        # got HTTP response but no pattern matched
        if port in config.HTTPS_PORTS:
            return ServiceInfo(service_name="HTTPS", version="")
        return ServiceInfo(service_name="HTTP", version="")
        #Debug mode results.
    banner = grab_banner(host, port, timeout)
        # Passive banner grabbing if not HTTP or no response from HTTP probe
    if banner:
        for pattern, service_name in config.BANNER_PATTERNS:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
            # try to get version from capture group if one exists
            # re.search returns a Match object — call .group(1) to get 
            # the first capture group (the part inside parentheses in the pattern)
            # but not all patterns have a capture group, so wrap in try/except
                try:
                    version = match.group(1).strip()
                except IndexError:
                    version = ""
                return ServiceInfo(service_name=service_name, version=version)
            
        return ServiceInfo(service_name=banner[:40], version="")
    
    if port in config.PORT_SERVICE_MAP:
        service_name, version = config.PORT_SERVICE_MAP[port]
        return ServiceInfo(service_name=service_name, version=version)
    
    return None