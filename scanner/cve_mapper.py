import requests
import config
from models import CVEEntry
from scanner.cache import get_cached, save_cache, init_cache


CPE_MAP = config.CPE_MAP

def build_cpe(service_name: str, version: str) -> str | None:
    key = service_name.lower().strip()
    base = CPE_MAP.get(key)
    if not base:
        return None
    if version:
        return f"{base}:{version}:*:*:*:*:*:*:*"
    return f"{base}:*:*:*:*:*:*:*:*"

def query_nvd(cpe: str) -> list:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {}
    if config.NVD_API_KEY:
        headers["nvdApiKey"] = config.NVD_API_KEY
    
    params = {"cpeName": cpe, "resultsPerPage": 20}
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        return response.json().get("vulnerabilities", [])
    except requests.RequestException:
        return []
    
def parse_cve(vuln: dict) -> CVEEntry:
    cve = vuln["cve"]
    cve_id = cve["id"]
    
    # description — take the first English one
    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d["lang"] == "en"), ""
    )[:300]
    
    # CVSS score — try v3.1 first, fall back to v2
    metrics = cve.get("metrics", {})
    score = 0.0
    severity = "UNKNOWN"
    
    if "cvssMetricV31" in metrics:
        cvss = metrics["cvssMetricV31"][0]["cvssData"]
        score    = cvss.get("baseScore", 0.0)
        severity = cvss.get("baseSeverity", "UNKNOWN")
    elif "cvssMetricV2" in metrics:
        cvss = metrics["cvssMetricV2"][0]["cvssData"]
        score    = cvss.get("baseScore", 0.0)
        severity = "MEDIUM"   # v2 has no severity label, default to MEDIUM
    
    return CVEEntry(
        cve_id=cve_id,
        description=description,
        severity=severity,
        cvss_score=score
    )
    
def map_cves(service_info) -> list[CVEEntry]:
    if not service_info or not service_info.service_name:
        return []
    
    cpe = build_cpe(service_info.service_name, service_info.version)
    if not cpe:
        return []
    
    # check cache first
    cached = get_cached(cpe)
    if cached is not None:
        # cached is a list of dicts — rebuild CVEEntry objects
        return [CVEEntry(**c) for c in cached]
    
    # not cached — query NVD
    vulns = query_nvd(cpe)
    cves  = [parse_cve(v) for v in vulns]
    
    # save to cache as list of dicts
    save_cache(cpe, [vars(c) for c in cves])
    
    return cves