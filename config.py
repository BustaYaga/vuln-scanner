from dotenv import load_dotenv
import os

load_dotenv()   # reads .env file and loads vars into environment

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


#--------------------------Full list of ports for reference: ------------------------------#
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