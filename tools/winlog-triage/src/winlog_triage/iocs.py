from __future__ import annotations

import ipaddress
import re

RE_URL = re.compile(r'\bhttps?://[^\s"\'<>]+', re.IGNORECASE)
RE_DOMAIN = re.compile(r'\b(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}\b')
RE_IPV4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
RE_MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')
RE_SHA1 = re.compile(r'\b[a-fA-F0-9]{40}\b')
RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
RE_EMAIL = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}')


def _valid_ipv4(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


def extract_iocs(s: str) -> dict[str, list[str]]:
    if not s:
        return {"urls": [], "domains": [], "ipv4": [], "md5": [], "sha1": [], "sha256": [], "emails": []}
    urls = set(RE_URL.findall(s))
    domains = {d for d in RE_DOMAIN.findall(s) if not any(d in u for u in urls)}
    ips = {candidate for candidate in RE_IPV4.findall(s) if _valid_ipv4(candidate)}
    return {
        "urls": sorted(urls),
        "domains": sorted(domains),
        "ipv4": sorted(ips),
        "md5": sorted(set(RE_MD5.findall(s))),
        "sha1": sorted(set(RE_SHA1.findall(s))),
        "sha256": sorted(set(RE_SHA256.findall(s))),
        "emails": sorted(set(RE_EMAIL.findall(s))),
    }
