import socket
from models import ScanResult
#from concurrent.futures import ThreadPoolExecutor

def scan_port(target: str, port: int, timeout: float = 1.0) -> PortResult | None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        result = s.connect_ex((target, port))
        if result == 0:
            return PortResult(port=port, protocol="tcp", state="open")
    return None
    try:
        result = s.connect_ex((target, port))
        if result == 0:
            return PortResult(port=port, protocol="tcp", state="open")
        return PortResult(port=port, protocol="tcp", state="closed")
    except socket.timeout:
        return PortResult(port=port, protocol="tcp", state="filtered")
    except socket.error:
        return None

# def scan_range(target: str, ports: list[int], timeout: float, workers: int) -> list[PortResult]:
#     results = []
#     with ThreadPoolExecutor(max_workers=workers) as executor:
#         futures = [executor.submit(scan_port, target, port, timeout) for port in ports]
#         for future in futures:
#             res = future.result()
#             if res:
#                 results.append(res)
#     return sorted(results, key=lambda x: x.port)

def parse_ports(port_string: str) -> list[int]:
    ports = set()
    for part in port_string.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return ports