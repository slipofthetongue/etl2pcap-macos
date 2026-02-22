from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from .etl_converter import convert_etl_to_pcapng

_LARGE_FILE_THRESHOLD = 500 * 1024 * 1024
_PROGRESS_INTERVAL = 0.25


def _make_progress_callback():
    start = time.monotonic()
    last_print = [0.0]

    def callback(total_events: int, packet_events: int) -> None:
        now = time.monotonic()
        if now - last_print[0] < _PROGRESS_INTERVAL:
            return
        last_print[0] = now

        elapsed = now - start
        rate = total_events / elapsed if elapsed > 0 else 0
        spinner = r"-\|/"[int(now * 4) % 4]
        sys.stderr.write(
            f"\r  {spinner}  Events: {total_events:>8,}   Packets found: {packet_events:>6,}"
            f"   ({rate:,.0f} events/s)    "
        )
        sys.stderr.flush()

    return callback


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="etl2pcap-macos",
        description=(
            "Convert Windows ETL network traces to PCAPNG on macOS/Linux.\n\n"
            "Supported capture sources:\n"
            "  netsh trace start capture=yes  (Microsoft-Windows-NDIS-PacketCapture)\n"
            "  pktmon start --capture --trace  (Microsoft-Windows-PktMon)\n\n"
            "Only event IDs known to carry raw packet data are processed; all\n"
            "other events are counted as skipped and reported in the output."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--input", required=True, type=Path, help="Input .etl file")
    parser.add_argument("--output", required=True, type=Path, help="Output .pcapng file")
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Raise an error when a known packet-bearing event yields no "
            "extractable payload.  Useful when debugging provider profiles."
        ),
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=None,
        metavar="N",
        help="Stop after writing N packets.  Useful for quick inspection of large captures.",
    )
    parser.add_argument(
        "--debug-events",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Write one JSON object per event to this file (JSONL format). "
            "Each line contains provider, event ID, field names, and raw values. "
            "Use this to diagnose missing packets or identify new field patterns."
        ),
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    input_size = 0
    try:
        input_size = os.path.getsize(args.input)
    except OSError:
        pass

    if input_size >= _LARGE_FILE_THRESHOLD:
        mb = input_size // (1024 * 1024)
        print(
            f"[warning] Input file is {mb} MB.  Processing is single-threaded and "
            "fully streaming, but very large captures may take several minutes."
        )

    progress = _make_progress_callback()

    stats = convert_etl_to_pcapng(
        input_path=args.input,
        output_path=args.output,
        strict=args.strict,
        debug_events_path=args.debug_events,
        max_packets=args.max_packets,
        progress_callback=progress,
    )

    sys.stderr.write("\r" + " " * 70 + "\r")
    sys.stderr.flush()

    print(f"Total events read:        {stats.total_events:,}")
    print(f"  Skipped (event ID):     {stats.skipped_event_id:,}")
    print(f"  Skipped (no payload):   {stats.skipped_no_payload:,}")
    if stats.reordered_packets:
        print(f"  Reordered packets:      {stats.reordered_packets:,}  (out-of-order in ETL buffer, sorted before write)")
    print(f"Packets written:          {stats.output_packets:,}")
    print(f"Wrote: {args.output}")


if __name__ == "__main__":
    main()
