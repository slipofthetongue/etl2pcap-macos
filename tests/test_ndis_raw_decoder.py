import struct

from etl2pcap_macos.etl_converter import _extract_ndis_raw_packet


class _Header:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload


class _Event:
    def __init__(self, payload: bytes) -> None:
        self.header = _Header(payload)


def _make_raw(medium_word: int, packet: bytes) -> bytes:
    """Build a minimal NDIS binary blob with the given medium word and packet."""
    return struct.pack("<III", medium_word, medium_word, len(packet)) + packet


NDIS_GUID = "6e00d62e-2947-0946-b423-3ee7bcd678ef"


def test_802_11_frame_has_linktype_105() -> None:
    """medium_word=12 → 802.11 radio frame → linktype 105."""
    packet = bytes.fromhex("88523000181deafa5fe102e80a7ee1a8") + b"\x00" * 32
    raw = _make_raw(12, packet)

    decoded, linktype = _extract_ndis_raw_packet(_Event(raw), NDIS_GUID)

    assert linktype == 105
    assert decoded is not None


def test_802_11_frame_control_bit6_cleared() -> None:
    """802.11 frame-control To DS flag (bit 6 of byte 1) is cleared."""
    # byte[1] = 0x5A → bit6 set → should become 0x1A after normalization
    packet = bytes.fromhex("88" + "5A" + "3000181deafa5fe102e80a7ee1a8") + b"\x00" * 30
    raw = _make_raw(12, packet)

    decoded, linktype = _extract_ndis_raw_packet(_Event(raw), NDIS_GUID)

    assert linktype == 105
    assert decoded is not None
    assert decoded[1] == 0x1A  # 0x5A & 0xBF


def test_ethernet_frame_has_linktype_1() -> None:
    """medium_word != 12 → Ethernet frame → linktype 1, no byte modification."""
    # ARP broadcast: dst MAC ff:ff:ff:ff:ff:ff — byte[1] = 0xFF (bit6 set)
    # Must NOT be modified by the 802.11 normalization.
    arp_broadcast = bytes.fromhex(
        "ffffffffffff00155d5652c10806000108000604000100155d5652c1ac128001000000000000ac128a5d"
    )
    raw = _make_raw(85, arp_broadcast)

    decoded, linktype = _extract_ndis_raw_packet(_Event(raw), NDIS_GUID)

    assert linktype == 1
    assert decoded == arp_broadcast  # byte[1] must remain 0xFF, not 0xBF


def test_ethernet_multicast_not_corrupted() -> None:
    """Ethernet multicast dst MAC (e.g. 33:33:...) is returned unmodified."""
    # IPv6 multicast dst: 33:33:00:00:00:fb — byte[1] = 0x33 (bit6 set)
    mcast_frame = bytes.fromhex("3333000000fb00155d5652c186dd") + b"\x00" * 40
    raw = _make_raw(18, mcast_frame)

    decoded, linktype = _extract_ndis_raw_packet(_Event(raw), NDIS_GUID)

    assert linktype == 1
    assert decoded is not None
    assert decoded[1] == 0x33  # must not be corrupted to 0x13


def test_drops_metadata_record() -> None:
    """48-byte records starting with 0x80 0x01 are NDIS metadata, not frames."""
    packet = b"\x80\x01" + (b"\x00" * 46)
    raw = _make_raw(12, packet)

    decoded, linktype = _extract_ndis_raw_packet(_Event(raw), NDIS_GUID)

    assert linktype == 105
    assert decoded == b""


def test_unknown_provider_returns_none() -> None:
    """Events from an unrecognised provider are not processed."""
    packet = b"\x08\x00" + b"\x00" * 20
    raw = _make_raw(12, packet)

    decoded, linktype = _extract_ndis_raw_packet(_Event(raw), "00000000-0000-0000-0000-000000000000")

    assert decoded is None
    assert linktype == 1
