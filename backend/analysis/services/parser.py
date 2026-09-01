import ipaddress
import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
IP_RE = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.I)

def _body(message):
    plain, html = [], []
    for part in message.walk() if message.is_multipart() else [message]:
        if part.get_content_disposition() == "attachment":
            continue
        try:
            content = part.get_content()
        except Exception:
            continue
        if part.get_content_type() == "text/plain" and isinstance(content, str):
            plain.append(content)
        elif part.get_content_type() == "text/html" and isinstance(content, str):
            html.append(content)
    return "\n".join(plain), "\n".join(html)

def _ip_record(value):
    try:
        ip = ipaddress.ip_address(value)
        kind = "public" if ip.is_global else "private/reserved"
        return {"value": value, "classification": kind}
    except ValueError:
        return {"value": value, "classification": "malformed"}

def _received(headers):
    hops = []
    for index, raw in enumerate(reversed(headers), 1):
        ips = IP_RE.findall(raw)
        timestamp = raw.rsplit(";", 1)[-1].strip() if ";" in raw else ""
        try:
            timestamp = parsedate_to_datetime(timestamp).isoformat()
        except Exception:
            pass
        hops.append({"index": index, "raw": raw, "ips": [_ip_record(ip) for ip in ips], "timestamp": timestamp, "trust": "unverified"})
    if hops:
        hops[-1]["trust"] = "recipient boundary"
    return hops

def parse_email(raw):
    message = BytesParser(policy=policy.default).parsebytes(raw)
    text, html = _body(message)
    headers_blob = "\n".join(f"{k}: {v}" for k, v in message.items())
    searchable = "\n".join([headers_blob, text, html])
    urls = sorted(set(URL_RE.findall(searchable)))
    domains = set(DOMAIN_RE.findall(searchable))
    domains.update(urlparse(url).hostname for url in urls if urlparse(url).hostname)
    ips = sorted(set(IP_RE.findall(searchable)))
    addresses = sorted(set(addr.lower() for _, addr in getaddresses(message.get_all("from", []) + message.get_all("to", []) + message.get_all("reply-to", []) + message.get_all("return-path", [])) if addr))
    attachments = [{"filename": part.get_filename() or "unnamed", "content_type": part.get_content_type()} for part in message.walk() if part.get_content_disposition() == "attachment"]
    return {
        "metadata": {
            "from": str(message.get("From", "")), "to": str(message.get("To", "")),
            "reply_to": str(message.get("Reply-To", "")), "return_path": str(message.get("Return-Path", "")),
            "subject": str(message.get("Subject", "")), "date": str(message.get("Date", "")),
            "message_id": str(message.get("Message-ID", "")),
        },
        "body": {"text": text[:20000], "html_present": bool(html)},
        "authentication_headers": [str(v) for v in message.get_all("Authentication-Results", [])],
        "received": _received([str(v) for v in message.get_all("Received", [])]),
        "indicators": {"urls": urls, "domains": sorted(d.lower() for d in domains), "ips": [_ip_record(ip) for ip in ips], "emails": addresses, "attachments": attachments},
    }

