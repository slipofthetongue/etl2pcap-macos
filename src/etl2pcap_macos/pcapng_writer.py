from __future__ import annotations

import struct
from pathlib import Path
from typing import IO, Iterable, Protocol


class PacketLike(Protocol):
    ts_ns: int
    iface: int
    payload: bytes
    linktype: int


_SECTION_HEADER_BLOCK = 0x0A0D0D0A
_INTERFACE_DESCRIPTION_BLOCK = 0x00000001
_ENHANCED_PACKET_BLOCK = 0x00000006

_LINKTYPE_ETHERNET = 1


def _pad4(data: bytes) -> bytes:
    pad_len = (4 - (len(data) % 4)) % 4
    if pad_len == 0:
        return data
    return data + (b"\x00" * pad_len)


def _build_block(block_type: int, body: bytes) -> bytes:
    total_length = 12 + len(body)
    return struct.pack("<II", block_type, total_length) + body + struct.pack("<I", total_length)


def _section_header_block() -> bytes:
    body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    return _build_block(_SECTION_HEADER_BLOCK, body)


def _interface_description_block(linktype: int = _LINKTYPE_ETHERNET, snaplen: int = 0x0000FFFF) -> bytes:
    body = struct.pack("<HHi", linktype, 0, snaplen)
    return _build_block(_INTERFACE_DESCRIPTION_BLOCK, body)


def _enhanced_packet_block(interface_id: int, timestamp_ns: int, packet_data: bytes) -> bytes:
    ts_us = max(0, timestamp_ns // 1_000)
    ts_high = (ts_us >> 32) & 0xFFFFFFFF
    ts_low = ts_us & 0xFFFFFFFF

    cap_len = len(packet_data)
    orig_len = cap_len
    body = struct.pack(
        "<IIIII",
        interface_id,
        ts_high,
        ts_low,
        cap_len,
        orig_len,
    )
    body += _pad4(packet_data)
    return _build_block(_ENHANCED_PACKET_BLOCK, body)


class PcapngWriter:
    """Streaming PCAPNG writer. Use as a context manager."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._fh: IO[bytes] | None = None
        self._iface_map: dict[tuple[int, int], int] = {}

    def __enter__(self) -> PcapngWriter:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self._path.open("wb")
        self._fh.write(_section_header_block())
        return self

    def __exit__(self, *_: object) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def write_packet(self, record: PacketLike) -> None:
        assert self._fh is not None, "PcapngWriter must be used as a context manager"
        linktype = int(getattr(record, "linktype", _LINKTYPE_ETHERNET))
        key = (record.iface, linktype)
        if key not in self._iface_map:
            idb_index = len(self._iface_map)
            self._iface_map[key] = idb_index
            self._fh.write(_interface_description_block(linktype=linktype))
        self._fh.write(
            _enhanced_packet_block(
                interface_id=self._iface_map[key],
                timestamp_ns=record.ts_ns,
                packet_data=record.payload,
            )
        )


def write_pcapng(path: Path, records: Iterable[PacketLike]) -> None:
    with PcapngWriter(path) as writer:
        for record in records:
            writer.write_packet(record)
