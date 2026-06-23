import requests
import config
import re
from models import WebFingerprint

def fetch_page(url: str, timeout: float) -> tuple[int, dict, str] | None:
    try:
        response = requests.get(
            url,
            timeout=timeout,
            verify=False,              # ignore SSL errors on scan targets
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        return response.status_code, dict(response.headers), response.text
    except:
        return None
    
def check_signature(host: str, port: int, app_name: str,
                    sig: dict, timeout: float) -> WebFingerprint | None:

    scheme = "https" if port in config.HTTPS_PORTS else "http"
    base_url = f"{scheme}://{host}:{port}"

    # try each known path
    for path in sig["paths"]:
        result = fetch_page(base_url + path, timeout)
        if not result:
            continue
        status, headers, body = result

        if status in (200, 401, 403):   # 401/403 still means it exists
            # check keyword matches in body
            for keyword in sig["keywords"]:
                if keyword.lower() in body.lower():
                    version = extract_version(base_url, sig, timeout)
                    return WebFingerprint(
                        app_name=app_name.title(),
                        version=version,
                        confidence="HIGH",
                        evidence=f"{path} returned {status} with keyword '{keyword}'"
                    )
            # check header matches
            for header in sig["headers"]:
                if header.lower() in {k.lower() for k in headers}:
                    version = extract_version(base_url, sig, timeout)
                    return WebFingerprint(
                        app_name=app_name.title(),
                        version=version,
                        confidence="HIGH",
                        evidence=f"Header '{header}' found"
                    )
    return None

def extract_version(base_url: str, sig: dict, timeout: float) -> str:
    result = fetch_page(base_url + sig["version_endpoint"], timeout)
    if not result:
        return ""
    _, _, body = result
    match = re.search(sig["version_pattern"], body)
    return match.group(1) if match else "" 

def fingerprint_web(host: str, port: int,
                    timeout: float) -> WebFingerprint | None:
    for app_name, sig in config.WEB_SIGNATURES.items():
        result = check_signature(host, port, app_name, sig, timeout)
        if result:
            return result
    return None