"""Traffic classification: domain -> category, IP -> geo/ASN/ISP.

Uses lightweight built-in heuristics by default so the agent runs anywhere.
If MaxMind GeoLite2 databases are present (GeoLite2-Country.mmdb / -ASN.mmdb in
the state dir) they are used for authoritative geo/ASN enrichment.
"""
from __future__ import annotations

import ipaddress
import logging
import random
from pathlib import Path
from typing import Optional

log = logging.getLogger("fabric.agent.classify")

# Coarse domain -> category map (extend / override from policy hints).
CATEGORY_KEYWORDS = {
    "social-media": ["facebook", "instagram", "twitter", "x.com", "tiktok", "snapchat", "linkedin", "reddit"],
    "streaming": ["youtube", "netflix", "twitch", "hulu", "spotify", "disneyplus", "primevideo"],
    "cloud": ["amazonaws", "azure", "googleapis", "cloudflare", "akamai", "fastly", "gcp"],
    "productivity": ["office", "microsoft", "google", "slack", "zoom", "atlassian", "notion", "dropbox"],
    "developer": ["github", "gitlab", "npmjs", "pypi", "docker", "stackoverflow"],
    "finance": ["paypal", "stripe", "chase", "bankofamerica", "coinbase", "fidelity"],
    "news": ["cnn", "bbc", "nytimes", "reuters", "bloomberg", "theguardian"],
    "malware": ["malware", "phish", "c2", "botnet", "ransom"],
    "advertising": ["doubleclick", "adservice", "adnxs", "criteo", "taboola"],
    "gaming": ["steam", "epicgames", "riotgames", "playstation", "xbox"],
}

_HIGH_RISK = {"malware", "phishing", "advertising"}


class Classifier:
    def __init__(self, state_dir: Optional[Path] = None):
        self._geo_country = None
        self._geo_asn = None
        if state_dir:
            self._try_load_geoip(state_dir)

    def _try_load_geoip(self, state_dir: Path) -> None:
        try:
            import geoip2.database  # type: ignore
            c = state_dir / "GeoLite2-Country.mmdb"
            a = state_dir / "GeoLite2-ASN.mmdb"
            if c.exists():
                self._geo_country = geoip2.database.Reader(str(c))
            if a.exists():
                self._geo_asn = geoip2.database.Reader(str(a))
        except Exception:
            pass

    # ------------------------------------------------------------ domains
    def classify_domain(self, domain: str) -> str:
        d = (domain or "").lower()
        if not d:
            return ""
        for cat, keys in CATEGORY_KEYWORDS.items():
            if any(k in d for k in keys):
                return cat
        return "uncategorized"

    def risk_for(self, category: str) -> int:
        if category in _HIGH_RISK:
            return 90
        if category in ("uncategorized", "gaming", "streaming"):
            return 30
        return 10

    # ------------------------------------------------------------ IPs
    def classify_ip(self, ip: str) -> dict:
        info = {"country": "", "asn": 0, "isp": "", "geo": {}}
        if not ip:
            return info
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return info
        if addr.is_private:
            info["country"] = "--"
            info["isp"] = "private"
            return info
        if self._geo_country:
            try:
                r = self._geo_country.country(ip)
                info["country"] = r.country.iso_code or ""
                info["geo"] = {"lat": r.location.latitude, "lon": r.location.longitude} if r.location else {}
            except Exception:
                pass
        if self._geo_asn:
            try:
                r = self._geo_asn.asn(ip)
                info["asn"] = r.autonomous_system_number or 0
                info["isp"] = r.autonomous_system_organization or ""
            except Exception:
                pass
        return info


# ---------------------------------------------------------------- simulation
# domain, ip, category, country, asn, isp, lat, lon, app, zone
_SIM_SITES = [
    ("youtube.com", "142.250.72.14", "streaming", "US", 15169, "Google LLC", 37.42, -122.08, "YouTube", "internet"),
    ("github.com", "140.82.113.3", "developer", "US", 36459, "GitHub Inc.", 37.77, -122.42, "GitHub", "internet"),
    ("netflix.com", "44.242.5.10", "streaming", "US", 2906, "Netflix Streaming", 45.52, -122.68, "Netflix", "internet"),
    ("office.com", "52.109.12.20", "productivity", "US", 8075, "Microsoft", 47.60, -122.33, "Microsoft 365", "internet"),
    ("facebook.com", "157.240.22.35", "social-media", "IE", 32934, "Meta Platforms", 53.34, -6.26, "Facebook", "internet"),
    ("amazonaws.com", "3.5.140.2", "cloud", "US", 16509, "Amazon.com", 39.04, -77.48, "AWS", "internet"),
    ("bbc.co.uk", "151.101.0.81", "news", "GB", 54113, "Fastly", 51.50, -0.12, "BBC", "internet"),
    ("malware-test.ru", "185.220.101.5", "malware", "RU", 205100, "BadHost", 55.75, 37.61, "Unknown", "internet"),
    ("tiktok.com", "23.211.4.10", "social-media", "SG", 20940, "Akamai", 1.35, 103.81, "TikTok", "internet"),
    ("stripe.com", "18.66.147.20", "finance", "US", 16509, "Amazon.com", 39.04, -77.48, "Stripe", "internet"),
    ("steampowered.com", "104.85.3.9", "gaming", "US", 20940, "Akamai", 40.71, -74.00, "Steam", "internet"),
    ("doubleclick.net", "142.250.72.34", "advertising", "US", 15169, "Google LLC", 37.42, -122.08, "Google Ads", "internet"),
    # private-network destinations reached via the corp connector
    ("jira.corp.internal", "10.10.4.20", "internal-app", "--", 0, "private", 0.0, 0.0, "Jira", "private"),
    ("gitlab.corp.internal", "10.10.4.30", "internal-app", "--", 0, "private", 0.0, 0.0, "GitLab", "private"),
    ("fileshare.corp.internal", "10.20.8.5", "file-share", "--", 0, "private", 0.0, 0.0, "SMB", "private"),
]

# Per-app request texture so drill-downs show realistic HTTP/TLS heuristics.
_APP_PATHS = {
    "YouTube": ["/watch", "/api/stats/playback", "/youtubei/v1/player"],
    "GitHub": ["/", "/api/v3/repos", "/login/oauth/access_token"],
    "Microsoft 365": ["/owa/", "/api/v2.0/me/messages", "/common/oauth2/token"],
    "Stripe": ["/v1/charges", "/v1/payment_intents"],
    "Jira": ["/rest/api/2/issue", "/secure/Dashboard.jspa"],
    "GitLab": ["/api/v4/projects", "/users/sign_in"],
    "SMB": ["/finance/2024", "/hr/policies"],
}
_CONTENT_TYPES = ["text/html", "application/json", "application/octet-stream", "video/mp4", "image/webp"]
_TLS_VERSIONS = ["TLS 1.3", "TLS 1.2"]
_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/17.4",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5) Mobile Safari/605.1",
]
_METHODS = ["GET", "GET", "GET", "POST", "PUT"]


def _rand_ja3() -> str:
    import hashlib
    return hashlib.md5(str(random.random()).encode()).hexdigest()


def sample_simulated_flow(endpoint_ids: list[str]) -> dict:
    domain, ip, cat, country, asn, isp, lat, lon, app, zone = random.choice(_SIM_SITES)
    verdict = "denied" if cat in ("malware", "advertising") and random.random() < 0.7 else "allowed"
    method = random.choice(_METHODS)
    path = random.choice(_APP_PATHS.get(app, ["/"]))
    status = 200 if verdict == "allowed" else 403
    content_type = random.choice(_CONTENT_TYPES)
    tls = random.choice(_TLS_VERSIONS)
    tx = random.randint(500, 50000)
    rx = random.randint(1000, 500000)
    meta = {
        "destination_zone": zone,
        "http_host": domain,
        "http_method": method,
        "http_path": path,
        "http_status": status,
        "content_type": content_type,
        "user_agent": random.choice(_UAS),
        "tls_version": tls,
        "ja3s": _rand_ja3()[:32],
        "cipher": random.choice(["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "ECDHE-RSA-AES128-GCM-SHA256"]),
        "inspected": bool(random.random() < 0.7),
        "bytes_up": tx,
        "bytes_down": rx,
        "packets": random.randint(8, 900),
        "payload_sample": (method + " " + path + " HTTP/2  host=" + domain),
    }
    return {
        "domain": domain, "sni": domain, "dst_ip": ip, "dst_port": 443,
        "protocol": "tcp", "category": cat, "app": app, "country": country, "asn": asn, "isp": isp,
        "ja3": _rand_ja3()[:32],
        "verdict": verdict, "risk": 90 if cat == "malware" else (50 if cat == "advertising" else 20),
        "tx_bytes": tx, "rx_bytes": rx,
        "duration_ms": random.randint(12, 4200),
        "meta": meta,
        "geo": {"lat": lat, "lon": lon, "city": ""},
        "endpoint_id": random.choice(endpoint_ids) if endpoint_ids else "",
        "user_uid": random.choice(["alice", "bob", "carol", "dave"]),
    }


def sample_simulated_dns() -> dict:
    domain, ip, cat, country, asn, isp, lat, lon, app, zone = random.choice(_SIM_SITES)
    action = "block" if cat in ("malware", "advertising") and random.random() < 0.6 else "resolve"
    qtype = random.choice(["A", "A", "AAAA", "HTTPS", "CNAME"])
    return {
        "qname": domain, "qtype": qtype, "answer": "" if action == "block" else ip,
        "category": cat, "action": action,
        "client_ip": f"100.64.0.{random.randint(2, 250)}",
        "user_uid": random.choice(["alice", "bob", "carol", "dave"]),
        "latency_ms": random.randint(1, 60),
        "meta": {
            "app": app, "destination_zone": zone, "resolver": "fabric-100.64.0.1",
            "answers": [] if action == "block" else [ip],
            "ttl": random.choice([30, 60, 300, 3600]),
            "upstream": "1.1.1.1" if zone == "internet" else "corp-dns",
            "blocklist": "threat-intel" if action == "block" else "",
        },
    }
