import socket
import config
import re
from models import ServiceInfo


def grab_banner(host: str, port: int, timeout: float) -> str | None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            banner = s.recv(1024)        # read up to 1024 bytes
            return banner.decode("utf-8", errors="ignore").strip()
        except:
            return None
        
        
def detect_service(host: str, port: int, timeout: float) -> ServiceInfo | None:
    # stage 1: try banner grab
    banner = grab_banner(host, port, timeout)
    
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