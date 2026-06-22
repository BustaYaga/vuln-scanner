import sqlite3
import json
import os
from datetime import datetime, timedelta
import config

CACHE_EXPIRY_DAYS = config.CACHE_EXPIRY_DAYS

def init_cache() -> None:
    with sqlite3.connect(config.DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS vuln_cache (
                cve_id TEXT PRIMARY KEY,
                data TEXT,
                timestamp DATETIME
            )
        ''')
        conn.commit()
        
def get_cached(cpe: str) -> dict | None:
    with sqlite3.connect(config.DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT data, timestamp FROM vuln_cache WHERE cve_id = ?', (cpe,))
        row = c.fetchone()
        if row:
            data, timestamp_str = row
            timestamp = datetime.fromisoformat(timestamp_str)
            if datetime.now() - timestamp < timedelta(days=CACHE_EXPIRY_DAYS):
                return json.loads(data)
    return None

def save_cache(cpe: str, cves: list) -> None:
    with sqlite3.connect(config.DB_PATH) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO vuln_cache (cve_id, data, timestamp) VALUES (?, ?, ?)",
            (cpe, json.dumps(cves), datetime.now().isoformat())
        )
        conn.commit()