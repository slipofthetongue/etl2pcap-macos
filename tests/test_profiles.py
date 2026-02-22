from etl2pcap_macos.profiles import normalize_bytes, select_profile, NDIS_NETSH_PROFILE, PKTMON_PROFILE


def test_normalize_bytes_from_hex_string() -> None:
    data = normalize_bytes("001122334455")
    assert data == bytes.fromhex("001122334455")


def test_normalize_bytes_from_int_list() -> None:
    data = normalize_bytes([0, 1, 2, 255])
    assert data == b"\x00\x01\x02\xff"


def test_normalize_bytes_rejects_invalid_string() -> None:
    assert normalize_bytes("not-hex") is None


def test_select_profile_ndis() -> None:
    assert select_profile("Microsoft-Windows-NDIS-PacketCapture") is NDIS_NETSH_PROFILE


def test_select_profile_pktmon() -> None:
    assert select_profile("microsoft-windows-pktmon") is PKTMON_PROFILE


def test_ndis_profile_known_event_ids() -> None:
    assert 1001 in NDIS_NETSH_PROFILE.known_event_ids
    assert 1006 in NDIS_NETSH_PROFILE.known_event_ids
    assert 9999 not in NDIS_NETSH_PROFILE.known_event_ids


def test_pktmon_profile_known_event_ids() -> None:
    assert 170 in PKTMON_PROFILE.known_event_ids
    assert 171 in PKTMON_PROFILE.known_event_ids
    assert 1 not in PKTMON_PROFILE.known_event_ids


def test_ndis_profile_default_linktype() -> None:
    # default_linktype is a fallback; actual link type is determined per-frame
    # by _extract_ndis_raw_packet using the medium word in the binary header.
    assert NDIS_NETSH_PROFILE.default_linktype == 1


def test_pktmon_profile_default_linktype() -> None:
    # pktmon captures Ethernet frames
    assert PKTMON_PROFILE.default_linktype == 1
