from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import struct
from typing import Any, Iterable

from dissect.etl import ETL

from .pcapng_writer import PcapngWriter, write_pcapng
from .profiles import normalize_bytes, normalize_key, select_profile


@dataclass(frozen=True)
class PacketRecord:
    ts_ns: int
    iface: int
    payload: bytes
    provider: str
    event_id: int | None
    linktype: int = 1


@dataclass(frozen=True)
class ConversionStats:
    total_events: int
    skipped_event_id: int      # events skipped because event ID not in known set
    skipped_no_payload: int    # events where no packet payload could be found
    reordered_packets: int     # packets whose ETW timestamp was out-of-order (still written, sorted)
    packet_events: int         # events that yielded a packet
    output_packets: int        # packets written to the PCAPNG file


# Provider GUIDs for the NDIS-PacketCapture ETW provider.  The same logical
# provider may appear under different GUIDs across Windows versions.
_NDIS_PACKETCAPTURE_GUIDS = {
    "2ed6006e-4729-4609-b423-3ee7bcd678ef",
    "6e00d62e-2947-0946-b423-3ee7bcd678ef",
}

# Minimum bytes for a valid Ethernet frame (14-byte header + 1 payload byte)
_MIN_ETHERNET_BYTES = 14


def _to_epoch_ns(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1_000_000_000)


def _try_get(event: Any, name: str) -> Any:
    try:
        if not hasattr(event, name):
            return None
        value = getattr(event, name)
    except Exception:
        return None

    if callable(value):
        try:
            return value()
        except TypeError:
            return value
        except Exception:
            return None
    return value


def _extract_provider(event: Any, values: dict[str, Any]) -> str:
    for key in ("Provider_Name", "provider_name", "ProviderName"):
        raw = values.get(key)
        if isinstance(raw, str) and raw:
            return raw

    for name in ("provider_name", "provider", "providerid", "provider_id", "provider_guid"):
        provider = _try_get(event, name)
        if provider:
            return str(provider)

    header = _try_get(event, "header")
    if header is not None:
        for name in ("provider_id", "providerid", "provider_guid"):
            provider = _try_get(header, name)
            if provider:
                return str(provider)

    return "unknown"


def _extract_event_id(event: Any, values: dict[str, Any]) -> int | None:
    for key in ("EventDescriptor_Id", "event_id", "id"):
        raw = values.get(key)
        if isinstance(raw, int):
            return raw
    for name in ("event_id", "id"):
        raw = _try_get(event, name)
        if isinstance(raw, int):
            return raw

    header = _try_get(event, "header")
    if header is not None:
        descriptor = _try_get(header, "descriptor")
        if descriptor is not None:
            raw_id = _try_get(descriptor, "id")
            if isinstance(raw_id, int):
                return raw_id
        for name in ("id", "opcode"):
            raw = _try_get(header, name)
            if isinstance(raw, int):
                return raw
    return None


def _extract_iface(values: dict[str, Any], preferred_iface_fields: Iterable[str]) -> int:
    normalized = {normalize_key(str(k)): v for k, v in values.items()}

    for key in preferred_iface_fields:
        candidate = normalized.get(normalize_key(key))
        if isinstance(candidate, int) and candidate >= 0:
            return candidate
        if isinstance(candidate, str) and candidate.isdigit():
            return int(candidate)

    for path, candidate in _iter_nodes(values):
        if not _path_has_token(path, ("if", "iface", "interface", "component")):
            continue
        if isinstance(candidate, int) and candidate >= 0:
            return candidate
        if isinstance(candidate, str) and candidate.isdigit():
            return int(candidate)

    return 0


def _iter_nodes(value: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], Any]]:
    yield from _iter_nodes_limited(value, path=path, seen=set(), depth=0, max_depth=8)


def _iter_nodes_limited(
    value: Any,
    *,
    path: tuple[str, ...],
    seen: set[int],
    depth: int,
    max_depth: int,
) -> Iterable[tuple[tuple[str, ...], Any]]:
    yield path, value
    if depth >= max_depth:
        return

    complex_node = isinstance(value, (dict, list, tuple)) or hasattr(value, "__dict__")
    if complex_node:
        obj_id = id(value)
        if obj_id in seen:
            return
        seen.add(obj_id)

    if isinstance(value, dict):
        for key, nested in value.items():
            yield from _iter_nodes_limited(
                nested,
                path=path + (normalize_key(str(key)),),
                seen=seen,
                depth=depth + 1,
                max_depth=max_depth,
            )
        return

    if isinstance(value, (list, tuple)):
        for idx, nested in enumerate(value):
            yield from _iter_nodes_limited(
                nested,
                path=path + (str(idx),),
                seen=seen,
                depth=depth + 1,
                max_depth=max_depth,
            )
        return

    attrs = getattr(value, "__dict__", None)
    if isinstance(attrs, dict) and attrs:
        for key, nested in attrs.items():
            if str(key).startswith("_"):
                continue
            yield from _iter_nodes_limited(
                nested,
                path=path + (normalize_key(str(key)),),
                seen=seen,
                depth=depth + 1,
                max_depth=max_depth,
            )


def _path_has_token(path: tuple[str, ...], tokens: tuple[str, ...]) -> bool:
    joined = ".".join(path)
    return any(token in joined for token in tokens)


def _find_payload(
    values: dict[str, Any],
    preferred_payload_fields: Iterable[str],
) -> bytes | None:
    normalized_items: list[tuple[str, Any]] = [
        (normalize_key(str(key)), value) for key, value in values.items()
    ]
    by_name = {k: v for k, v in normalized_items}

    for preferred in preferred_payload_fields:
        raw = by_name.get(normalize_key(preferred))
        payload = normalize_bytes(raw)
        if payload and len(payload) >= _MIN_ETHERNET_BYTES:
            return payload

    best: bytes | None = None
    for path, raw in _iter_nodes(values):
        payload = normalize_bytes(raw)
        if not payload or len(payload) < _MIN_ETHERNET_BYTES:
            continue
        if _path_has_token(path, ("packet", "payload", "data", "fragment", "frame")):
            if best is None or len(payload) > len(best):
                best = payload

    return best


def _extract_ndis_raw_packet(event: Any, provider: str) -> tuple[bytes | None, int]:
    """Parse the length-prefixed binary payload from an NDIS-PacketCapture record.
    Returns (packet_bytes, linktype) or (None, 1) if not applicable/invalid.
    """
    if provider.lower() not in _NDIS_PACKETCAPTURE_GUIDS:
        return None, 1

    header = _try_get(event, "header")
    if header is None:
        return None, 1

    raw = normalize_bytes(_try_get(header, "payload"))
    if not raw or len(raw) < 12:
        return None, 1

    medium_word = struct.unpack_from("<I", raw, 0)[0]
    packet_len = struct.unpack_from("<I", raw, 8)[0]
    if packet_len <= 0 or 12 + packet_len > len(raw):
        return None, 1

    packet = bytearray(raw[12 : 12 + packet_len])

    if packet_len == 48 and packet[:2] == b"\x80\x01":
        return b"", 105  # NDIS metadata record, not a frame

    if medium_word == 12:
        # 802.11: clear "To DS" flag (bit 6 of frame-control byte 1)
        if len(packet) > 1 and (packet[1] & 0x40):
            packet[1] &= 0xBF
        return bytes(packet), 105
    else:
        return bytes(packet), 1


def _event_values(event: Any) -> dict[str, Any]:
    for attr in ("event_values", "values", "payload", "event_data", "data", "user_data"):
        raw = _try_get(event, attr)
        if isinstance(raw, dict):
            return raw
        if raw is not None and hasattr(raw, "items"):
            try:
                return dict(raw.items())
            except Exception:
                pass

    return {}


def _event_timestamp_ns(event: Any) -> int:
    for attr in ("ts", "timestamp", "time_created"):
        ts = _try_get(event, attr)
        if isinstance(ts, datetime):
            return _to_epoch_ns(ts)

    header = _try_get(event, "header")
    if header is not None:
        for attr in ("timestamp", "time_stamp", "timecreated"):
            ts = _try_get(header, attr)
            if isinstance(ts, datetime):
                return _to_epoch_ns(ts)

    return 0


def _jsonable(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    return str(value)


def _event_attribute_keys(event: Any) -> list[str]:
    keys: list[str] = []
    slots = getattr(type(event), "__slots__", ())
    if isinstance(slots, str):
        slots = (slots,)
    if isinstance(slots, (tuple, list)):
        for key in slots:
            name = str(key)
            if name and not name.startswith("_"):
                keys.append(name)
    for name in dir(event):
        if name.startswith("_") or name in keys:
            continue
        value = _try_get(event, name)
        if callable(value):
            continue
        keys.append(name)
    return sorted(set(keys))


def _write_debug_row(
    fh: Any,
    provider: str,
    event_id: int | None,
    has_packet: bool,
    payload_len: int,
    values: dict[str, Any],
    event: Any,
) -> None:
    row = {
        "provider": provider,
        "event_id": event_id,
        "has_packet": has_packet,
        "payload_len": payload_len,
        "keys": sorted(str(k) for k in values.keys()),
        "event_attr_keys": _event_attribute_keys(event),
        "values": _jsonable(values),
    }
    fh.write(json.dumps(row) + "\n")


def convert_etl_to_pcapng(
    input_path: Path,
    output_path: Path,
    *,
    strict: bool = False,
    debug_events_path: Path | None = None,
    max_packets: int | None = None,
    progress_callback: Any = None,
) -> ConversionStats:
    total_events = 0
    skipped_event_id = 0
    skipped_no_payload = 0
    packet_events = 0
    records: list[PacketRecord] = []

    debug_handle = None
    if debug_events_path is not None:
        debug_events_path.parent.mkdir(parents=True, exist_ok=True)
        debug_handle = debug_events_path.open("w", encoding="utf-8")

    try:
        with input_path.open("rb") as fh:
            etl = ETL(fh)
            for event in etl:
                total_events += 1

                if max_packets is not None and packet_events >= max_packets:
                    break

                values = _event_values(event)
                provider = _extract_provider(event, values)
                event_id = _extract_event_id(event, values)
                profile = select_profile(provider)

                if profile.known_event_ids and event_id not in profile.known_event_ids:
                    skipped_event_id += 1
                    if debug_handle is not None:
                        _write_debug_row(debug_handle, provider, event_id, False, 0, values, event)
                    if progress_callback is not None:
                        progress_callback(total_events, packet_events)
                    continue

                payload, linktype = _extract_ndis_raw_packet(event, provider)

                if payload is None:
                    linktype = profile.default_linktype
                    payload = _find_payload(values, profile.preferred_payload_fields)

                if payload == b"":
                    payload = None

                if payload is None:
                    skipped_no_payload += 1
                    if strict and profile.known_event_ids and event_id in profile.known_event_ids:
                        raise ValueError(
                            f"No packet payload found for provider={provider} event_id={event_id}"
                        )
                    if debug_handle is not None:
                        _write_debug_row(debug_handle, provider, event_id, False, 0, values, event)
                    if progress_callback is not None:
                        progress_callback(total_events, packet_events)
                    continue

                ts_ns = _event_timestamp_ns(event)
                iface = _extract_iface(values, profile.preferred_iface_fields)
                records.append(PacketRecord(
                    ts_ns=ts_ns,
                    iface=iface,
                    payload=payload,
                    provider=provider,
                    event_id=event_id,
                    linktype=linktype,
                ))
                packet_events += 1

                if debug_handle is not None:
                    _write_debug_row(debug_handle, provider, event_id, True, len(payload), values, event)

                if progress_callback is not None:
                    progress_callback(total_events, packet_events)

    finally:
        if debug_handle is not None:
            debug_handle.close()

    # ETL buffers are per-CPU, so events may arrive out of timestamp order.
    records.sort(key=lambda r: r.ts_ns)

    reordered = 0
    last_ts = 0
    for r in records:
        if r.ts_ns < last_ts:
            reordered += 1
        last_ts = r.ts_ns

    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_pcapng(output_path, records)

    return ConversionStats(
        total_events=total_events,
        skipped_event_id=skipped_event_id,
        skipped_no_payload=skipped_no_payload,
        reordered_packets=reordered,
        packet_events=packet_events,
        output_packets=len(records),
    )

