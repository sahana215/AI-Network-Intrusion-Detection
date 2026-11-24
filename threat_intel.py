import ipaddress
import json
import os
import sqlite3
import time
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "database" / "blackbox_threat_intel.db"

# Curated offline high-fidelity threat indicators for immediate offline threat enrichment
KNOWN_THREAT_DATABASE = {
    # Tor Exit Nodes / Anonymous Proxies
    "185.220.101.4": {"type": "Tor Exit Node", "score": 85, "asn": "AS208294", "country": "DE", "source": "Tor Directory"},
    "185.220.101.5": {"type": "Tor Exit Node", "score": 85, "asn": "AS208294", "country": "DE", "source": "Tor Directory"},
    "185.220.101.6": {"type": "Tor Exit Node", "score": 85, "asn": "AS208294", "country": "DE", "source": "Tor Directory"},
    "198.98.56.143": {"type": "Tor Exit Node", "score": 88, "asn": "AS53667", "country": "US", "source": "Tor Directory"},
    "51.15.43.205":  {"type": "Tor Exit Node", "score": 82, "asn": "AS12876", "country": "FR", "source": "Tor Directory"},
    # Known Scanning / Reconnaissance Engines
    "162.142.125.0": {"type": "Automated Port Scanner (Censys)", "score": 65, "asn": "AS398722", "country": "US", "source": "Censys Research"},
    "198.20.99.130": {"type": "Internet Scanner (Shodan)", "score": 60, "asn": "AS14061", "country": "US", "source": "Shodan Sensor"},
    "71.6.232.4":    {"type": "Internet Scanner (Shadowserver)", "score": 50, "asn": "AS25820", "country": "US", "source": "Shadowserver"},
    # Known Malicious C2 / Botnet IPs
    "194.26.29.42":  {"type": "Mirai / IoT Botnet Scanner", "score": 95, "asn": "AS44477", "country": "RU", "source": "Abuse Threat Feed"},
    "45.148.10.15":  {"type": "Cobalt Strike C2 Server", "score": 98, "asn": "AS200019", "country": "NL", "source": "FireEye / Mandiant Feed"},
    "193.106.191.95":{"type": "Brute Force / Exploit Probe", "score": 92, "asn": "AS48693", "country": "RU", "source": "Spamhaus DROP"},
    "91.240.118.172":{"type": "Credential Stuffing Source", "score": 90, "asn": "AS60117", "country": "UA", "source": "Emerging Threats"},
    # Public Safe Resolvers
    "8.8.8.8":        {"type": "Public DNS Resolver (Google)", "score": 0, "asn": "AS15169", "country": "US", "source": "Google Public DNS"},
    "8.8.4.4":        {"type": "Public DNS Resolver (Google)", "score": 0, "asn": "AS15169", "country": "US", "source": "Google Public DNS"},
    "1.1.1.1":        {"type": "Public DNS Resolver (Cloudflare)", "score": 0, "asn": "AS13335", "country": "US", "source": "Cloudflare DNS"},
    "1.0.0.1":        {"type": "Public DNS Resolver (Cloudflare)", "score": 0, "asn": "AS13335", "country": "US", "source": "Cloudflare DNS"},
    "9.9.9.9":        {"type": "Quad9 Secure Resolver", "score": 0, "asn": "AS19281", "country": "US", "source": "Quad9"},
}


class ThreatIntelEngine:
    """Provides threat intelligence enrichment, IP reputation analysis, and caching."""

    def __init__(self, db_path=DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=30000;")
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ip_reputation_cache (
                    ip TEXT PRIMARY KEY,
                    reputation_score INTEGER,
                    status TEXT,
                    threat_type TEXT,
                    country TEXT,
                    asn TEXT,
                    source TEXT,
                    details TEXT,
                    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    @staticmethod
    def is_private_or_bogon(ip_str):
        """Checks if an IP string is an RFC 1918 private, loopback, or non-routable bogon IP."""
        if not ip_str or ip_str in ("Unknown", "0.0.0.0", "-"):
            return True, "Unknown / Unspecified"
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private:
                return True, "RFC 1918 Private LAN Address"
            if ip_obj.is_loopback:
                return True, "Loopback Interface (Localhost)"
            if ip_obj.is_reserved or ip_obj.is_multicast:
                return True, "Reserved / Multicast Space"
            return False, "Public Routable Address"
        except ValueError:
            return True, "Invalid IP Address Format"

    def lookup_ip(self, ip_str, abuseipdb_key=None):
        """Looks up reputation for an IP address. Checks cache, private IP filter,

        offline threat feed, and external API if key is supplied.
        """
        ip_clean = str(ip_str).strip()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 1. Check if private or bogon
        is_priv, priv_reason = self.is_private_or_bogon(ip_clean)
        if is_priv:
            return {
                "ip": ip_clean,
                "reputation_score": 0,
                "status": "INTERNAL",
                "threat_type": priv_reason,
                "country": "Local LAN",
                "asn": "Private Subnet",
                "source": "RFC 1918 Subnet Validator",
                "details": f"Local host address ({priv_reason}). Not routable over the public internet.",
                "verified": True,
                "last_checked": now_str,
            }

        # 2. Check local SQLite cache
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT reputation_score, status, threat_type, country, asn, source, details FROM ip_reputation_cache WHERE ip = ?",
                    (ip_clean,)
                )
                row = cursor.fetchone()
                if row:
                    return {
                        "ip": ip_clean,
                        "reputation_score": row[0],
                        "status": row[1],
                        "threat_type": row[2],
                        "country": row[3],
                        "asn": row[4],
                        "source": f"{row[5]} (Cached)",
                        "details": row[6],
                        "verified": True,
                        "last_checked": now_str,
                    }
        except Exception:
            pass

        # 3. Check curated offline threat intelligence database
        if ip_clean in KNOWN_THREAT_DATABASE:
            entry = KNOWN_THREAT_DATABASE[ip_clean]
            score = entry["score"]
            status = "MALICIOUS" if score >= 75 else ("SUSPICIOUS" if score >= 40 else "CLEAN")
            res = {
                "ip": ip_clean,
                "reputation_score": score,
                "status": status,
                "threat_type": entry["type"],
                "country": entry["country"],
                "asn": entry["asn"],
                "source": entry["source"],
                "details": f"Identified in {entry['source']} as {entry['type']}.",
                "verified": True,
                "last_checked": now_str,
            }
            self._cache_reputation(res)
            return res

        # 4. Optional live query to AbuseIPDB if API key provided
        key = abuseipdb_key or os.getenv("ABUSEIPDB_API_KEY")
        if key:
            try:
                import requests
                headers = {"Key": key, "Accept": "application/json"}
                url = "https://api.abuseipdb.com/api/v2/check"
                params = {"ipAddress": ip_clean, "maxAgeInDays": 90}
                resp = requests.get(url, headers=headers, params=params, timeout=2.0)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    score = int(data.get("abuseConfidenceScore", 0))
                    country = data.get("countryCode", "Unknown")
                    isp = data.get("isp", "Unknown")
                    status = "MALICIOUS" if score >= 50 else ("SUSPICIOUS" if score >= 20 else "CLEAN")
                    res = {
                        "ip": ip_clean,
                        "reputation_score": score,
                        "status": status,
                        "threat_type": "Reported Malicious Host" if score >= 50 else "Public Host",
                        "country": country,
                        "asn": isp,
                        "source": "AbuseIPDB Live v2 API",
                        "details": f"Confidence score {score}%. Reports: {data.get('totalReports', 0)}.",
                        "verified": True,
                        "last_checked": now_str,
                    }
                    self._cache_reputation(res)
                    return res
            except Exception:
                pass  # Fall through to unverified result on timeout or network block

        # 5. Fallback for unlisted public IP (neutral / unverified)
        res = {
            "ip": ip_clean,
            "reputation_score": 0,
            "status": "UNVERIFIED",
            "threat_type": "No Prior Malicious Record",
            "country": "Unknown",
            "asn": "Unlisted Public IP",
            "source": "BLACKBOX Threat Intelligence Hub",
            "details": "Public routable IP. No threat intelligence flags or blacklistings recorded.",
            "verified": False,
            "last_checked": now_str,
        }
        return res

    def _cache_reputation(self, rep_dict):
        try:
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO ip_reputation_cache
                    (ip, reputation_score, status, threat_type, country, asn, source, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    rep_dict["ip"],
                    rep_dict["reputation_score"],
                    rep_dict["status"],
                    rep_dict["threat_type"],
                    rep_dict["country"],
                    rep_dict["asn"],
                    rep_dict["source"],
                    rep_dict["details"]
                ))
                conn.commit()
        except Exception:
            pass


def get_ip_reputation(ip_address, api_key=None):
    engine = ThreatIntelEngine()
    return engine.lookup_ip(ip_address, api_key)
