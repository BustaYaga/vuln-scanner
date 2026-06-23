from dotenv import load_dotenv
import os

load_dotenv()   # reads .env file and loads vars into environment

#-----------------------------Global-Configuration-----------------------------------------#
DEBUGGING      = False #os.getenv("DEBUGGING", "False").lower() == "true"
CACHE_EXPIRY_DAYS = 7   # re-query NVD after 7 days
NVD_API_KEY    = os.getenv("NVD_API_KEY", "") #if na then second arg is default
DEFAULT_PORTS  = [21,22,23,25,53,80,110,135,139,143,443,445,3389,8080]
PORT_PROFILES  = {
                    "quick":  "21,22,23,25,53,80,110,135,139,143,443,445,3389,8080",
                    "web":    "80,443,8080,8443,8008,3000,5000,9000",
                    "ad":     "53,88,135,139,389,445,464,636,3268,3269,5985,5986",
                    "full":   "1-65535",
                    "common": "1-1024",
                }
THREAD_COUNT   = int(os.getenv("THREAD_COUNT", "100"))
TIMEOUT        = float(os.getenv("TIMEOUT", "1.0"))
OUTPUT_DIR     = os.getenv("OUTPUT_DIR", "results")
DB_PATH        = os.getenv("DB_PATH", "vuln_db.sqlite")


#--------------------------Full-list-of-ports-for-reference:-------------------------------#

#80,443,8080,8443,8008,3000,5000 WEB PORTS
#22,23,3389,5900,5901,4444 REMOTE ACCESS PORTS
#53,88,135,137,138,139,389,445,464,636,3268,3269,5985,5986,49152-65535 AD PORTS
#25,110,143,465,587,993,995 EMAIL PORTS
#1433,1521,3306,5432,6379,27017,5984,9200,9042 DATABASE PORTS
#20,21,69,115,2049,445 FILE TRANSFER PORTS
#67,68,123,161,162,179,514,520 NETWORK INFRASTRUCTURE PORTS
#2375,2376,2379,6443,9090,3100,8161,15672,9000 MONITORING & DEVOPS PORTS
#500,1194,1723,4500,51820,8291 SECURITY & VPN PORTS
#389,515,631,9100 PRINTING & DIRECTORY PORTS

#----------------------------------Service-Detector-----------------------------------------#

PROBE_PATHS = ["/", "/index.html", "/index.php", "/.well-known/"]
HTTP_PORTS = {80, 443, 8080, 8443, 8008, 3000, 5000, 8888}
HTTPS_PORTS = {443, 8443}

BANNER_PATTERNS = [
    (r"SSH-[\d.]+-(.+)",            "SSH"),
    (r"220[ -].*FTP",               "FTP"),
    (r"220 .* ESMTP",               "SMTP"),
    (r"Server:\s*([^\r\n]+)",       "HTTP"),   # ← specific match first
    (r"X-Powered-By:\s*([^\r\n]+)", "HTTP"),
    (r"HTTP/[\d.]+",                "HTTP"),   # ← generic fallback last
    (r"RFB [\d.]+",                 "VNC"),
]
  
PORT_SERVICE_MAP = {
    21:   ("FTP",        ""),
    22:   ("SSH",        ""),
    23:   ("Telnet",     ""),
    25:   ("SMTP",       ""),
    53:   ("DNS",        ""),
    80:   ("HTTP",       ""),
    110:  ("POP3",       ""),
    135:  ("RPC",        ""),
    139:  ("NetBIOS",    ""),
    143:  ("IMAP",       ""),
    443:  ("HTTPS",      ""),
    445:  ("SMB",        ""),
    3306: ("MySQL",      ""),
    3389: ("RDP",        ""),
    5432: ("PostgreSQL", ""),
    6379: ("Redis",      ""),
    8080: ("HTTP-Alt",   ""),
}

#-------------------------------------CVE-Mapper-------------------------------------------#

CPE_MAP = {
    "ssh":        "cpe:2.3:a:openbsd:openssh",
    "apache":     "cpe:2.3:a:apache:http_server",
    "nginx":      "cpe:2.3:a:nginx:nginx",
    "ftp":        "cpe:2.3:a:microsoft:ftp_service",
    "smtp":       "cpe:2.3:a:postfix:postfix",
    "mysql":      "cpe:2.3:a:mysql:mysql",
    "rdp":        "cpe:2.3:a:microsoft:remote_desktop_protocol",
    "smb":        "cpe:2.3:a:microsoft:smb",
    "rpc":        "cpe:2.3:a:microsoft:rpc",
    "postgresql": "cpe:2.3:a:postgresql:postgresql",
    "redis":      "cpe:2.3:a:redis:redis",
}

#----------------------------------Web-Fingerprinting---------------------------------------#

WEB_SIGNATURES = {
    "wordpress": {
        "paths":    ["/wp-login.php", "/wp-admin/", "/wp-json/"],
        "keywords": ["wp-content", "wp-includes", "WordPress"],
        "headers":  [],
        "version_endpoint": "/wp-json/",
        "version_pattern":  r'"version":"([\d.]+)"',
        "cpe_base": "cpe:2.3:a:wordpress:wordpress",
    },
    "joomla": {
        "paths":    ["/administrator/", "/components/"],
        "keywords": ["Joomla!", "joomla"],
        "headers":  ["x-content-encoded-by"],
        "version_endpoint": "/administrator/manifests/files/joomla.xml",
        "version_pattern":  r"<version>([\d.]+)</version>",
        "cpe_base": "cpe:2.3:a:joomla:joomla",
    },
    "drupal": {
        "paths":    ["/user/login", "/core/misc/drupal.js"],
        "keywords": ["Drupal", "drupal.org"],
        "headers":  ["x-generator"],
        "version_endpoint": "/CHANGELOG.txt",
        "version_pattern":  r"Drupal ([\d.]+)",
        "cpe_base": "cpe:2.3:a:drupal:drupal",
    },
    "phpmyadmin": {
        "paths":    ["/phpmyadmin/", "/pma/", "/phpMyAdmin/"],
        "keywords": ["phpMyAdmin", "PMA_VERSION"],
        "headers":  [],
        "version_endpoint": "/phpmyadmin/README",
        "version_pattern":  r"phpMyAdmin ([\d.]+)",
        "cpe_base": "cpe:2.3:a:phpmyadmin:phpmyadmin",
    },
    "jenkins": {
        "paths":    ["/jenkins/", "/login?from=%2F"],
        "keywords": ["Jenkins", "hudson"],
        "headers":  ["x-jenkins"],
        "version_endpoint": "/login",
        "version_pattern":  r"Jenkins ver\. ([\d.]+)",
        "cpe_base": "cpe:2.3:a:jenkins:jenkins",
    },
    "grafana": {
        "paths":    ["/grafana/", "/login"],
        "keywords": ["Grafana", "grafana"],
        "headers":  ["x-grafana-id"],
        "version_endpoint": "/api/health",
        "version_pattern":  r'"version":"([\d.]+)"',
        "cpe_base": "cpe:2.3:a:grafana:grafana",
    },
    "tomcat": {
        "paths":    ["/manager/html", "/host-manager/"],
        "keywords": ["Apache Tomcat", "Tomcat"],
        "headers":  [],
        "version_endpoint": "/",
        "version_pattern":  r"Apache Tomcat/([\d.]+)",
        "cpe_base": "cpe:2.3:a:apache:tomcat",
    },
    "freepbx": {
    "paths":    ["/admin/config.php", "/recordings/", "/panel/"],
    "keywords": ["FreePBX", "Asterisk", "PBX"],
    "headers":  ["x-freepbx"],
    "version_endpoint": "/admin/config.php?display=dashboard",
    "version_pattern":  r"FreePBX ([\d.]+)",
    "cpe_base": "cpe:2.3:a:freepbx:freepbx",
    }
}