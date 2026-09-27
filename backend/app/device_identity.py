"""Device identity extraction - architecture-document.md §3 step 3b: runs
independently of whether the vendor's security-relevant syntax resolves, so
even a wholly unknown vendor's report still has device info in it.

Honest limitation, stated up front rather than discovered later: a plain
`show running-config` style export very often does NOT contain a serial
number at all - that typically comes from `show version` / `show
inventory`, a different command entirely. Fields we can't find are None, not
guessed or fabricated.
"""
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Optional


@dataclass
class DeviceIdentity:
    hostname: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    serial_number: Optional[str] = None


def extract(raw_text: str, fmt: str) -> DeviceIdentity:
    if fmt == "json":
        return _extract_json(raw_text)
    if fmt == "xml":
        return _extract_xml(raw_text)
    return _extract_cli(raw_text)


def _extract_cli(raw_text: str) -> DeviceIdentity:
    hostname = (_search(r"^hostname\s+\"?([^\"\s]+)", raw_text)
                or _search(r"^\s*(?:set system )?host-name\s+\"?([^\";\s]+)", raw_text)       # Junos
                or _search(r"^\s*set hostname\s+\"?([^\"\s]+)", raw_text))                  # FortiOS
    firmware_version = (_search(r"^version\s+([^;\s]+)", raw_text)
                        or _search(r"^!\s*device:.*\(\s*[^,]+,\s*([^)\s]+)", raw_text)      # Arista header
                        or _search(r"^#config-version=[^-]+-([\d.]+)", raw_text))              # FortiOS header
    model = (_search(r"^license udi pid\s+(\S+)", raw_text)                                   # Cisco UDI line
             or _search(r"^cisco\s+(\S+)\s+.*processor", raw_text, extra=re.IGNORECASE)        # show version
             or _search(r"^Model number\s*:\s*(\S+)", raw_text, extra=re.IGNORECASE)
             or _search(r"^!\s*device:.*\(\s*([^,)]+)", raw_text)                            # Arista header
             or _search(r"^#config-version=([^-]+)-", raw_text)                                 # FortiOS header
             or _search(r"^!\s*Model:\s*(\S+)", raw_text, extra=re.IGNORECASE))
    serial = (_search(r"^license udi pid\s+\S+\s+sn\s+(\S+)", raw_text)                    # Cisco UDI line
              or _search(r"Processor board ID\s+(\S+)", raw_text)                             # show version
              or _search(r"^System serial number\s*:\s*(\S+)", raw_text, extra=re.IGNORECASE)
              or _search(r"^!\s*Serial(?:\s*Number)?:\s*(\S+)", raw_text, extra=re.IGNORECASE))
    return DeviceIdentity(hostname=hostname, model=model, firmware_version=firmware_version, serial_number=serial)


def _search(pattern: str, text: str, extra: int = 0) -> Optional[str]:
    m = re.search(pattern, text, re.MULTILINE | extra)
    return m.group(1) if m else None


def _extract_json(raw_text: str) -> DeviceIdentity:
    try:
        obj = json.loads(raw_text)
    except (json.JSONDecodeError, ValueError):
        return DeviceIdentity()
    meta = (obj.get("DEVICE_METADATA") or {}).get("localhost") or {}
    return DeviceIdentity(
        hostname=meta.get("hostname"),
        # SONiC config_db.json commonly carries hwsku/platform on
        # DEVICE_METADATA - the closest thing to a "model" this file format
        # actually contains; still no serial number (that's a runtime/EEPROM
        # concept, not part of config_db.json).
        model=meta.get("hwsku") or meta.get("platform"),
        firmware_version=None,
        serial_number=None,
    )


def _extract_xml(raw_text: str) -> DeviceIdentity:
    try:
        root = ET.fromstring(raw_text)
    except ET.ParseError:
        return DeviceIdentity()
    system = root.find("system")
    hostname = system.findtext("hostname") if system is not None else None
    if not hostname:  # e.g. PAN-OS keeps it under devices/entry/deviceconfig/system
        hostname = next((e.text.strip() for e in root.iter("hostname") if e.text and e.text.strip()), None)
    version = root.findtext("version") or root.get("version")
    return DeviceIdentity(hostname=hostname, firmware_version=version, model=None, serial_number=None)
