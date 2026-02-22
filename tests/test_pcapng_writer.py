from pathlib import Path
import struct

from etl2pcap_macos.etl_converter import PacketRecord
from etl2pcap_macos.pcapng_writer import PcapngWriter, write_pcapng


_EPB_TYPE = 0x00000006
_IDB_TYPE = 0x00000001


def _count_blocks(data: bytes, block_type: int) -> int:
    count = 0
    i = 0
    while i + 12 <= len(data):
        btype, blen = struct.unpack_from("<II", data, i)
        if blen < 12:
            break
        if btype == block_type:
            count += 1
        i += blen
    return count


def test_write_and_read_pcapng(tmp_path: Path) -> None:
    out = tmp_path / "sample.pcapng"

    records = [
        PacketRecord(
            ts_ns=1_700_000_000_000_000_000,
            iface=0,
            payload=bytes.fromhex("00112233445566778899aabb08004500"),
            provider="test",
            event_id=1,
        ),
        PacketRecord(
            ts_ns=1_700_000_000_100_000_000,
            iface=1,
            payload=bytes.fromhex("aabbccddeeff00112233445508004500"),
            provider="test",
            event_id=2,
        ),
    ]

    write_pcapng(out, records)

    raw = out.read_bytes()
    assert _count_blocks(raw, _EPB_TYPE) == 2


def test_write_pcapng_preserves_linktype_per_interface(tmp_path: Path) -> None:
    out = tmp_path / "sample-linktype.pcapng"
    records = [
        PacketRecord(
            ts_ns=1_700_000_000_000_000_000,
            iface=0,
            payload=bytes.fromhex("0801008002e80a7ee1a8181deafa5fe1"),
            provider="test",
            event_id=1,
            linktype=105,
        )
    ]

    write_pcapng(out, records)
    raw = out.read_bytes()

    i = 0
    found_linktype = None
    while i + 12 <= len(raw):
        block_type, block_len = struct.unpack_from("<II", raw, i)
        if block_len < 12:
            break
        if block_type == _IDB_TYPE:
            found_linktype = struct.unpack_from("<H", raw, i + 8)[0]
            break
        i += block_len

    assert found_linktype == 105


def test_pcapng_writer_streaming(tmp_path: Path) -> None:
    out = tmp_path / "streaming.pcapng"
    records = [
        PacketRecord(
            ts_ns=1_700_000_000_000_000_000 + i * 1_000_000,
            iface=0,
            payload=bytes([i % 256] * 14),
            provider="test",
            event_id=1,
        )
        for i in range(10)
    ]

    with PcapngWriter(out) as writer:
        for r in records:
            writer.write_packet(r)

    raw = out.read_bytes()
    assert _count_blocks(raw, _EPB_TYPE) == 10


def test_pcapng_writer_multiple_interfaces_and_linktypes(tmp_path: Path) -> None:
    out = tmp_path / "multi.pcapng"
    records = [
        PacketRecord(ts_ns=1_000_000_000, iface=0, payload=b"\x00" * 14, provider="t", event_id=1, linktype=1),
        PacketRecord(ts_ns=2_000_000_000, iface=1, payload=b"\x01" * 14, provider="t", event_id=1, linktype=105),
        PacketRecord(ts_ns=3_000_000_000, iface=0, payload=b"\x02" * 14, provider="t", event_id=1, linktype=1),
    ]

    write_pcapng(out, records)
    raw = out.read_bytes()

    assert _count_blocks(raw, _IDB_TYPE) == 2
