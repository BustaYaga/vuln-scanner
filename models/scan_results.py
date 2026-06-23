from dataclasses    import dataclass, field
from datetime      import datetime

@dataclass
class CVEEntry:
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    
@dataclass
class ServiceInfo:
    service_name: str
    version: str
    cpe: str = ""

@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service_info: ServiceInfo | None = None
    cve_entries: list[CVEEntry] = field(default_factory=list)
    web_fingerprint: WebFingerprint | None = None

    @property
    def has_cves(self) -> bool:
        return len(self.cve_entries) > 0

    @property
    def highest_severity(self) -> str:
        if not self.cve_entries:
            return "NONE"

        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

        found = {entry.severity.upper() for entry in self.cve_entries}

        for level in order:
            if level in found:
                return level

        return "UNKNOWN"
        
@dataclass
class ScanResult: # Represents scan results | Top level container
    target: str
    scan_date: datetime = field(default_factory=datetime.now)
    port_results: list[PortResult] = field(default_factory=list)
    
    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.port_results if p.state == "open"]

    @property
    def vulnerable_ports(self) -> list[PortResult]:
        return [p for p in self.open_ports if p.has_cves]

    @property
    def total_cves(self) -> int:
        return sum(len(p.cve_entries) for p in self.port_results)
        
@dataclass
class WebFingerprint:
    app_name: str          # "WordPress"
    version: str           # "6.1.1" or "" if unknown
    confidence: str        # "HIGH" / "MEDIUM" / "LOW"
    evidence: str          # what gave it away e.g. "/wp-login.php returned 200"
    cves: list[CVEEntry] = field(default_factory=list)    
