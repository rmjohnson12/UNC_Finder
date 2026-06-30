"""Extract passive indicators from already-published report text."""
from __future__ import annotations

import ipaddress
import re

Ioc = tuple[str, str]

_SHA256_RE = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")
_MD5_RE = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])")
_URL_RE = re.compile(r"(?i)\bh(?:tt|xx)ps?://[^\s<>\"']+")
_IP_RE = re.compile(r"(?<![\w])(?:\d{1,3}(?:\.|\[\.\])){3}\d{1,3}(?![\w])")
_DOMAIN_RE = re.compile(
    r"(?i)(?<![@\w])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.|\[\.\]))+[a-z]{2,63}(?![\w-])"
)
_TRAILING_URL_PUNCTUATION = ".,;:!?)]}"
_FILE_EXTENSIONS = {
    "7z", "apk", "ashx", "bat", "bin", "dll", "doc", "docx", "exe",
    "hta", "ini", "jar", "jpeg", "jpg", "js", "lnk", "pdf", "png",
    "ps1", "rar", "rtf", "txt", "vbs", "xls", "xlsx", "zip",
}


def refang(value: str) -> str:
    """Normalize common defensive defanging without contacting the value."""
    normalized = re.sub(r"(?i)^hxxps://", "https://", value)
    normalized = re.sub(r"(?i)^hxxp://", "http://", normalized)
    return normalized.replace("[.]", ".")


def extract_iocs(text: str) -> list[Ioc]:
    """Return sorted, unique hashes, URLs, IPs, and domains from report text."""
    found: set[Ioc] = set()

    for value in _SHA256_RE.findall(text or ""):
        found.add(("file:hashes.'SHA-256'", value.lower()))
    for value in _MD5_RE.findall(text or ""):
        found.add(("file:hashes.MD5", value.lower()))
    for value in _URL_RE.findall(text or ""):
        normalized = refang(value).rstrip(_TRAILING_URL_PUNCTUATION)
        found.add(("url", normalized))
    for value in _IP_RE.findall(text or ""):
        normalized = refang(value)
        try:
            parsed = ipaddress.ip_address(normalized)
        except ValueError:
            continue
        if parsed.version == 4:
            found.add(("ipv4-addr", str(parsed)))
    for value in _DOMAIN_RE.findall(text or ""):
        normalized = refang(value).lower()
        if normalized.rsplit(".", 1)[-1] not in _FILE_EXTENSIONS:
            found.add(("domain-name", normalized))

    return sorted(found)
