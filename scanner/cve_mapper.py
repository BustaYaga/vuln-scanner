import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def query_cves(cpe_string: str, api_key: str | None = None) -> list[dict]:
    params = {"cpeName": cpe_string, "resultsPerPage": 20}
    headers = {"apiKey": api_key} if api_key else {}
    resp = requests.get(NVD_API, params=params, headers=headers, timeout=10)
    resp.raise_for_status()
    vulns = resp.json().get("vulnerabilities", [])
    return [
        {
            "cve_id": v["cve"]["id"],
            "severity": v["cve"].get("metrics", {})
                          .get("cvssMetricV31", [{}])[0]
                          .get("cvssData", {}).get("baseSeverity", "UNKNOWN"),
            "score": v["cve"].get("metrics", {})
                      .get("cvssMetricV31", [{}])[0]
                      .get("cvssData", {}).get("baseScore", 0.0),
            "description": v["cve"]["descriptions"][0]["value"][:200],
        }
        for v in vulns
    ]