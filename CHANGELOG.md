# Changelog

## 0.2.0 (2026-02-22)

### Breaking changes

- `ConversionStats` has four new fields (`skipped_event_id`, `skipped_no_payload`,
  `skipped_timestamp`) and the old `total_events` / `packet_events` fields are
  retained.  The `output_packets` field is now equal to `packet_events`.
- `ProviderProfile` gains two required fields: `known_event_ids` and
  `default_linktype`.  Any code constructing a `ProviderProfile` directly must
  be updated.
- The `--strict` flag now only raises on events whose event ID *is* in the
  profile's `known_event_ids` set.  Unknown event IDs are always skipped silently.

### New features

- **Streaming output** — PCAPNG is written incrementally as events are processed.
  No in-memory list of all packets is maintained.  Memory usage is now bounded by
  a single event at a time rather than the full capture.
- **Event-ID allowlisting** — each `ProviderProfile` now declares
  `known_event_ids`: the set of event descriptor IDs that are known to carry raw
  packet data.  Events outside this set are skipped immediately without any
  field-search work.  This eliminates spurious "payload found" false positives on
  metadata events and makes the skip counters meaningful.
- **`default_linktype` on `ProviderProfile`** — the PCAPNG link-layer type is now
  declared per-profile rather than always defaulting to Ethernet.  NDIS-
  PacketCapture defaults to 105 (IEEE 802.11 radio); pktmon defaults to 1
  (Ethernet).
- **Monotonic timestamp enforcement** — packets whose ETW timestamp is earlier
  than the previous written packet are dropped and counted in
  `skipped_timestamp`.  PCAPNG readers require monotonically non-decreasing
  timestamps.
- **`--max-packets N`** — stop after writing N packets.  Useful for quickly
  inspecting the start of a large capture without processing the whole file.
- **Large-file warning** — the CLI prints a warning when the input file exceeds
  500 MB.
- **Richer CLI output** — the summary now prints separate skip reason counts so
  it is immediately clear whether skipped events are expected (event-ID filter)
  or unexpected (no payload found).
- **GitHub Actions CI** — `.github/workflows/ci.yml` runs `pytest` on Python
  3.10, 3.11, and 3.12 on every push and pull request.

### Removed

- `_find_payload_from_event` — the attribute-walk fallback that searched event
  `__dict__` for any bytes-like value.  This was the source of most false
  positives (non-packet bytes being mistaken for frames).  The two-tier
  `_find_payload` (preferred field name → keyword path walk) is the only
  extraction path now.
- **Weak and fallback payload tiers** — only "preferred field name" and
  "keyword-bearing path" matches are accepted.  Bare large-bytes-valued fields
  with no packet-related keyword in their path are no longer returned.

### Fixed

- `PcapngWriter` is now a context manager (`with PcapngWriter(path) as w`),
  ensuring the file handle is always closed even if an exception occurs during
  conversion.

## 0.1.0 (initial release)

- ETL parser pipeline via `dissect.etl`
- Provider-aware payload extraction heuristics for netsh and pktmon ETLs
- Native PCAPNG writer (SHB, IDB, EPB blocks)
- Comparison tool (`etl2pcap-compare`) using SHA-256 payload hashes
- `--debug-events` JSONL output for field-name discovery
