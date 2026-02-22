from etl2pcap_macos.etl_converter import _find_payload


def test_find_payload_preferred_field_wins() -> None:
    """A field whose normalised name matches a preferred field is returned first."""
    values = {
        "PacketData": bytes.fromhex("00112233445566778899aabb080045000028"),
        "OtherBytes": bytes([0xFF] * 60),
    }
    payload = _find_payload(values, ("packetdata", "packet", "payload"))
    assert payload == bytes.fromhex("00112233445566778899aabb080045000028")


def test_find_payload_nested_dict() -> None:
    """Keyword-walk tier finds bytes in a nested structure via path token."""
    values = {
        "Outer": {
            "Meta": {"Len": 60},
            "PacketBlob": bytes.fromhex("00112233445566778899aabb080045000028"),
        }
    }
    payload = _find_payload(values, ("packetdata", "packet", "payload"))
    assert payload == bytes.fromhex("00112233445566778899aabb080045000028")


def test_find_payload_returns_none_when_only_small_bytes() -> None:
    """Values shorter than 14 bytes are never returned as packet payloads."""
    values = {"packet": b"\x00\x01\x02"}
    payload = _find_payload(values, ("packet",))
    assert payload is None


def test_find_payload_no_weak_fallback() -> None:
    """Bytes under a path with no packet-related keyword are not returned."""
    values = {
        "unrelated_field": bytes([0xAA] * 100),
    }
    # "unrelated_field" normalises to "unrelatedfield" which contains neither
    # a preferred-field name nor a keyword token → should return None.
    payload = _find_payload(values, ("packetdata", "packet", "payload"))
    assert payload is None
