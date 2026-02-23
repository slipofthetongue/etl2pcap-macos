# etl2pcap-macos

Convert Windows ETL network packet captures to PCAPNG on **macOS and Linux**. No Windows required.

These scripts are aimed at security researchers and network analysts who need to analyse Windows packet captures on macOS or Linux without access to a Windows machine or VM.

## Background

Tech support personnel and incident response teams working on corporate macOS or Linux machines often have to scramble to find a Windows host just to run Microsoft's native `etl2pcapng.exe` conversion tool. This is compounded by the fact that the ETL format is proprietary and the only way to parse it is through the ETW APIs (`OpenTrace`, `ProcessTrace`, etc.), which are Windows-exclusive, so there is no straightforward path to a native cross-platform implementation. ETL files produced by `netsh trace` and `pktmon` are the standard output format for Windows built-in packet capture, but they are unreadable by Wireshark without conversion first.

Specifically:

- Windows writes network captures as binary ETL (Event Trace Log) files using the ETW (Event Tracing for Windows) subsystem.
- Each ETL file contains thousands of events, the vast majority of which are metadata: session markers, filter status, component registration, counter snapshots. Only a small subset of event IDs actually carry raw frame bytes.
- The raw frame bytes are not stored in a standard named field. For `netsh` captures, they live in a length-prefixed binary blob in the ETW record header. The first four bytes of that blob (the *medium word*) determine whether the frame is Ethernet or IEEE 802.11 radio. For `pktmon`, the frame is in a named event field.
- On top of this, ETL files buffer events per-CPU, so packets from different NICs or CPU cores can appear interleaved and out of chronological order in the raw stream.

This tool was created to handle all of that: parse the ETL format, identify and extract only the real packet events, sort them by timestamp, and write a clean PCAPNG that Wireshark can open directly.

## Scripts

### `etl2pcap-macos` (CLI command)

The main conversion tool. Takes an `.etl` file as input and produces a `.pcapng` file ready for Wireshark.

- Parses the binary ETL format using [`dissect.etl`](https://github.com/fox-it/dissect.etl).
- Matches each event's provider name or GUID against built-in profiles for `netsh` and `pktmon`. Unrecognised providers use a generic fallback.
- Skips all events whose ID is not in the known packet-bearing set for that provider.
- For NDIS-PacketCapture events, reads the medium word at offset 0 of the binary header to determine layer-2 type: `12` = 802.11 radio (link type 105), anything else = Ethernet (link type 1).
- For 802.11 frames, clears the "To DS" flag (bit 6 of frame-control byte 1) before writing, matching `etl2pcapng.exe` behaviour.
- Collects all extracted frames, sorts them by ETW timestamp, and writes a spec-compliant PCAPNG. One Interface Description Block per unique `(interface_index, link_type)` pair, one Enhanced Packet Block per frame.
- Prints a live progress line while processing, and a summary on completion.

### `scripts/compare_captures.py` (standalone developer script)

A validation tool that compares two PCAP or PCAPNG files packet-for-packet using SHA-256 payload hashes. Useful for verifying that `etl2pcap-macos` output matches `etl2pcapng.exe` output on the same ETL file.

Requires `scapy` (not installed automatically — see [Validating output](#validating-output-against-etl2pcapngexe)).

## Requirements & assumptions

This tool is intentionally specific about what it supports.

### Required

- Python 3.10 or later
- One runtime dependency: [`dissect.etl`](https://github.com/fox-it/dissect.etl) (installed automatically)
- A completed `.etl` file produced by either `netsh trace` or `pktmon` on Windows 10 or 11

### Supported / tested scenarios

**Confirmed working:**

- `netsh trace` captures on Windows 10 and 11:
  - Mixed Wi-Fi captures (standard 802.11 data frames)
  - Mixed captures with both 802.11 frames and Ethernet frames (virtual switch)
  - Ethernet ARP broadcasts and IPv6 multicast
- `pktmon` captures on Windows 10 and 11:
  - TCP/IP captures over Ethernet

### Not supported (tool will skip or produce incomplete output)

- Live capture: input must be a completed `.etl` file.
- ETL files from ETW providers other than `netsh` and `pktmon`: a generic fallback applies but results may be incomplete.
- IP or 802.11 fragment reassembly: frames are written exactly as captured.
- Checksum validation: frames pass through without verification.

## Usage

### Get the tool

HTTPS:
```bash
git clone https://github.com/slipofthetongue/etl2pcap-macos.git
```

SSH:
```bash
git clone git@github.com:slipofthetongue/etl2pcap-macos.git
```

Enter the project directory:
```bash
cd etl2pcap-macos
```

### Install

The fastest way: `pipx` installs into an isolated environment and puts `etl2pcap-macos` on your PATH automatically:

```bash
pipx install .
```

If you don't have `pipx`:
```bash
brew install pipx
pipx ensurepath
```
Restart Terminal so PATH updates take effect.

Or install directly with pip into your current environment:
```bash
pip install .
```

### Capture on Windows

**Using `netsh trace`:**
```powershell
netsh trace start capture=yes report=no tracefile=C:\capture.etl
# ... reproduce traffic ...
netsh trace stop
```

**Using `pktmon`:**
```powershell
pktmon filter remove
pktmon start --capture --trace -f C:\capture.etl
# ... reproduce traffic ...
pktmon stop
```

### Transfer the ETL file

Copy the `.etl` file from the Windows machine to your macOS or Linux machine via USB, network share, SCP, whatever is convenient. The file does not need to be on a Windows volume; the tool reads it as plain bytes.

### Convert

```bash
etl2pcap-macos --input capture.etl --output capture.pcapng
```

A live progress line updates on stderr while processing. When done:

```
Total events read:        48,291
  Skipped (event ID):     45,103
  Skipped (no payload):   0
  Reordered packets:      31  (out-of-order in ETL buffer, sorted before write)
Packets written:          3,188
Wrote: capture.pcapng
```

`Skipped (event ID)` being large is completely normal. The vast majority of events in an ETL file are metadata, not frames.

### Open in Wireshark

```bash
wireshark capture.pcapng
```

Or drag the file onto Wireshark. No profile or dissector changes are needed. Wireshark reads the link type from the PCAPNG file directly and applies the correct dissector automatically (Ethernet or IEEE 802.11 radio depending on the capture source).

### All options

| Flag | Description |
|------|-------------|
| `--help` | Show available options and usage syntax |
| `--input PATH` | Source `.etl` file **(required)** |
| `--output PATH` | Destination `.pcapng` file **(required)** |
| `--max-packets N` | Stop after writing N packets — useful for quickly inspecting the start of a large capture |
| `--strict` | Exit with an error if a known packet-bearing event yields no extractable frame — useful when diagnosing missing packets |
| `--debug-events PATH` | Write one JSON record per event to a JSONL file — see [Troubleshooting](#troubleshooting) |

## Supported capture sources

### `netsh trace` — Microsoft-Windows-NDIS-PacketCapture

Packet-bearing event IDs processed:

| Event ID | Frame type |
|----------|------------|
| 1001 | WFP (Windows Filtering Platform) |
| 1002 | NDIS miniport inbound |
| 1003 | NDIS miniport outbound |
| 1004 | VIF (virtual interface) |
| 1005 | VM switch inbound |
| 1006 | VM switch outbound |

- Ethernet frames → PCAPNG link type 1
- IEEE 802.11 radio frames → PCAPNG link type 105

All other event IDs in the ETL (session metadata, filter events, etc.) are counted and skipped.

### `pktmon` — Microsoft-Windows-PktMon

Packet-bearing event IDs processed:

| Event ID | Frame type |
|----------|------------|
| 170 | Captured frame |
| 171 | Dropped frame (truncated, still useful) |

- Ethernet frames → PCAPNG link type 1

## Validating output against `etl2pcapng.exe`

A standalone comparison script is included at `scripts/compare_captures.py`. It compares two PCAP or PCAPNG files packet-for-packet using SHA-256 payload hashes and reports exactly how many packets match, how many are only in one file, and the overall result.

**One-time setup** (requires `scapy`, not part of the main install):
```bash
pip install scapy
```

**Usage:**
```bash
python scripts/compare_captures.py --left macos.pcapng --right windows.pcapng
```

**Example output:**
```
Left packets:  2292
Right packets: 2292
Shared packets by payload hash: 2292
Only left packets:  0
Only right packets: 0
Result: match
```

If the result is `mismatch`, the counts tell you how many packets are exclusive to each side. Use `--debug-events` on the ETL to identify which events are missing or producing different bytes.

## Limitations vs `etl2pcapng.exe`

- **Slower:** Pure Python, single-threaded. On captures with hundreds of thousands of events, expect it to take noticeably longer than the native Windows tool. A 500 MB input triggers a warning. For large captures, plan accordingly.

- **Field-name dependent:** Windows ETW provider schemas are not publicly documented. The tool identifies frames by matching against a hard-coded list of known field names. If a future Windows update renames those internal fields, fewer packets will be found. This is the most common cause of count discrepancy with `etl2pcapng.exe`. Adding support for a renamed field is a one-line change in `profiles.py`.

- **Two capture sources validated.** The built-in profiles have been tested against real captures from `netsh trace` and `pktmon`. Any other ETW provider falls back to a generic heuristic which may be incomplete.

- **No reassembly.** Raw frames are written exactly as captured (no 802.11 or IP fragment reassembly).

- **No checksum validation.** Frames pass through without any verification.

- **No live capture.** Input must be a completed `.etl` file.

## Troubleshooting

### Fewer packets than expected

Run with `--debug-events` to dump every event to a JSONL file:

```bash
etl2pcap-macos --input capture.etl --output capture.pcapng --debug-events events.jsonl
```

Each line in `events.jsonl` is one event:

```json
{
  "provider": "microsoft-windows-ndis-packetcapture",
  "event_id": 1001,
  "has_packet": true,
  "payload_len": 74,
  "keys": ["filterstatus", "ifindex", "packetdata"],
  "event_attr_keys": ["header", "timestamp", "values"],
  "values": { "ifindex": 3, "packetdata": "0011223344..." }
}
```

Filter for `has_packet: false` to find events being skipped and inspect what field names they expose. If you see a consistent field name containing frame bytes that is not in the current profile, add it to `preferred_payload_fields` in `src/etl2pcap_macos/profiles.py`.

### `Skipped (no payload)` is unexpectedly high

This usually means a known packet-bearing event ID exists in the ETL but the frame bytes are stored under an unrecognised field name. Use `--debug-events` to identify the field, then add it to the profile.

### Unknown provider

If your ETL comes from a provider not listed above, the generic fallback profile applies: no event-ID filter, keyword-based field search only. Results may be incomplete. Use `--debug-events` to inspect what fields the events expose, identify the bytes-valued field containing the frame, and add a `ProviderProfile` entry in `profiles.py`.

## Security notes / disclaimers

This tool does not modify any system state. It only reads an `.etl` file and writes a `.pcapng` file. There is no risk of impacting your network configuration, DNS, or any system service.

You are responsible for:

- Ensuring you have the right to analyse the capture file you are processing.
- Verifying the output is complete and accurate for your use case (use `scripts/compare_captures.py` against a Windows reference if in doubt).
- Understanding that field-name changes in future Windows releases may cause packet counts to drop without warning.

The tool comes with no warranty (see the MIT License). Use at your own risk.

If you have questions or feedback, you can drop me an email: eduardobarretor@gmail.com

## License

MIT License. See [LICENSE](LICENSE) for the full text.
