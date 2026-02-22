from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ProviderProfile:
    provider_names: tuple[str, ...]
    known_event_ids: tuple[int, ...]
    default_linktype: int
    preferred_payload_fields: tuple[str, ...]
    preferred_iface_fields: tuple[str, ...]


# Microsoft-Windows-NDIS-PacketCapture  (netsh trace capture=yes)
# Event IDs 1001-1006 carry raw frames; all others are metadata.
NDIS_NETSH_PROFILE = ProviderProfile(
    provider_names=(
        "microsoft-windows-ndis-packetcapture",
        "microsoft-windows-ndiscap",
    ),
    known_event_ids=(1001, 1002, 1003, 1004, 1005, 1006),
    default_linktype=1,
    preferred_payload_fields=(
        "packetdata",
        "packet",
        "fragment",
        "rawpacket",
        "data",
        "payload",
    ),
    preferred_iface_fields=(
        "ifindex",
        "interfaceindex",
        "ifidx",
        "interface",
        "nicindex",
    ),
)

# Microsoft-Windows-PktMon  (pktmon start --capture --trace)
# Event IDs 170 (captured frame) and 171 (drop with truncated frame).
PKTMON_PROFILE = ProviderProfile(
    provider_names=(
        "microsoft-windows-pktmon",
        "microsoft-windows-packetmonitor",
    ),
    known_event_ids=(170, 171),
    default_linktype=1,
    preferred_payload_fields=(
        "packet",
        "packetdata",
        "fragment",
        "payload",
        "rawpacket",
        "data",
    ),
    preferred_iface_fields=(
        "componentid",
        "ifindex",
        "interfaceindex",
        "nblinterfaceindex",
        "interface",
    ),
)

# Generic fallback for unrecognised providers.
GENERIC_PROFILE = ProviderProfile(
    provider_names=("*",),
    known_event_ids=(),
    default_linktype=1,
    preferred_payload_fields=(
        "packet",
        "packetdata",
        "fragment",
        "rawpacket",
        "payload",
        "data",
        "frame",
    ),
    preferred_iface_fields=(
        "ifindex",
        "interfaceindex",
        "interface",
        "componentid",
    ),
)

PROFILES: tuple[ProviderProfile, ...] = (
    NDIS_NETSH_PROFILE,
    PKTMON_PROFILE,
    GENERIC_PROFILE,
)


def select_profile(provider_name: str | None) -> ProviderProfile:
    if not provider_name:
        return GENERIC_PROFILE

    lowered = provider_name.lower()
    for profile in PROFILES:
        if any(name == lowered for name in profile.provider_names if name != "*"):
            return profile
    return GENERIC_PROFILE


def normalize_bytes(value: Any) -> bytes | None:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    if hasattr(value, "tobytes") and callable(value.tobytes):
        try:
            raw = value.tobytes()
            if isinstance(raw, bytes):
                return raw
        except Exception:
            pass

    if isinstance(value, (list, tuple)) and value:
        if all(isinstance(item, int) and 0 <= item <= 255 for item in value):
            return bytes(value)

    if isinstance(value, str):
        compact = "".join(ch for ch in value if ch.isalnum())
        compact = compact.lower()
        if compact.startswith("0x"):
            compact = compact[2:]
        if compact and len(compact) % 2 == 0 and all(ch in "0123456789abcdef" for ch in compact):
            try:
                return bytes.fromhex(compact)
            except ValueError:
                return None

    if value is not None and not isinstance(value, (str, int, float, bool)):
        try:
            raw = bytes(value)
            if raw:
                return raw
        except Exception:
            return None

    return None


def normalize_key(name: str) -> str:
    return "".join(ch for ch in name.lower() if ch.isalnum())
