"""Public IP selection and best-effort infrastructure enrichment."""
import ipaddress
import json
from functools import lru_cache
from urllib.parse import quote
from urllib.request import Request, urlopen

PROVIDER = "ipwho.is"
TIMEOUT_SECONDS = 5


def earliest_observable_public_ip(parsed):
    """Return the oldest public IP present in the parsed Received chain."""
    for hop in parsed.get("received", []):
        for item in hop.get("ips", []):
            if item.get("classification") == "public":
                return item["value"], hop
    return None, None


def _network_type(connection, security):
    if security.get("tor"):
        return "Tor exit node"
    if security.get("vpn"):
        return "VPN"
    if security.get("proxy"):
        return "Proxy"
    if security.get("hosting"):
        return "Hosting / data center"
    return connection.get("type") or "ISP / unknown"


@lru_cache(maxsize=256)
def enrich_ip(ip_value):
    try:
        ip = ipaddress.ip_address(ip_value)
    except ValueError:
        return {"ip": ip_value, "available": False, "error": "Invalid IP address"}
    if not ip.is_global:
        return {"ip": ip_value, "available": False, "error": "Private or reserved IP addresses are not geolocated"}

    request = Request(
        f"https://ipwho.is/{quote(str(ip), safe='')}",
        headers={"Accept": "application/json", "User-Agent": "ThreatLens/0.1"},
    )
    try:
        with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if not payload.get("success", True):
            raise ValueError(payload.get("message") or "IP intelligence provider rejected the lookup")
        connection = payload.get("connection") or {}
        security = payload.get("security") or {}
        return {
            "ip": str(ip),
            "available": True,
            "provider": PROVIDER,
            "location": {
                "country": payload.get("country"),
                "country_code": payload.get("country_code"),
                "region": payload.get("region"),
                "city": payload.get("city"),
                "latitude": payload.get("latitude"),
                "longitude": payload.get("longitude"),
                "timezone": (payload.get("timezone") or {}).get("id") if isinstance(payload.get("timezone"), dict) else payload.get("timezone"),
            },
            "network": {
                "asn": connection.get("asn"),
                "organization": connection.get("org"),
                "isp": connection.get("isp"),
                "domain": connection.get("domain"),
                "type": _network_type(connection, security),
            },
            "security": {
                "anonymous": bool(security.get("anonymous")),
                "proxy": bool(security.get("proxy")),
                "vpn": bool(security.get("vpn")),
                "tor": bool(security.get("tor")),
                "hosting": bool(security.get("hosting")),
            },
            "error": None,
        }
    except Exception as exc:
        return {
            "ip": str(ip),
            "available": False,
            "provider": PROVIDER,
            "error": f"{type(exc).__name__}: {exc}",
        }


def enrich_origin(parsed):
    ip_value, hop = earliest_observable_public_ip(parsed)
    if not ip_value:
        return {
            "ip": None,
            "available": False,
            "basis": "No public IP was found in the Received chain",
            "confidence": "insufficient evidence",
            "error": "Only private, reserved, malformed, or no relay IPs were present",
        }
    result = enrich_ip(ip_value)
    result.update({
        "basis": "Earliest observable public IP in the Received chain",
        "hop_index": hop.get("index"),
        "hop_trust": hop.get("trust"),
        "confidence": "infrastructure only",
        "caveat": "This identifies observable mail infrastructure, not the physical location or identity of the sender.",
    })
    return result
