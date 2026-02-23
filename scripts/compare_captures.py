"""Developer tool — to be used for debugging/tshooting

Compares packet payloads between two PCAP/PCAPNG files using SHA-256 hashes.
Useful for validating etl2pcap-macos output against etl2pcapng.exe reference captures.

Requirements (install separately):
    pip install scapy

Usage:
    python scripts/compare_captures.py --left macos.pcapng --right windows.pcapng
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
from pathlib import Path

from scapy.utils import PcapNgReader, PcapReader


@dataclass(frozen=True)
class CaptureSummary:
    packet_count: int
    unique_hashes: int
    hash_counter: Counter[str]


def _packet_hashes(path: Path) -> list[str]:
    reader_cls = PcapNgReader if path.suffix.lower() == ".pcapng" else PcapReader
    hashes: list[str] = []
    with reader_cls(str(path)) as reader:
        for packet in reader:
            raw = bytes(packet)
            hashes.append(hashlib.sha256(raw).hexdigest())
    return hashes


def summarize(path: Path) -> CaptureSummary:
    hashes = _packet_hashes(path)
    counter = Counter(hashes)
    return CaptureSummary(
        packet_count=len(hashes),
        unique_hashes=len(counter),
        hash_counter=counter,
    )


def compare(left: Path, right: Path) -> int:
    left_summary = summarize(left)
    right_summary = summarize(right)

    shared = left_summary.hash_counter & right_summary.hash_counter
    only_left = left_summary.hash_counter - right_summary.hash_counter
    only_right = right_summary.hash_counter - left_summary.hash_counter

    shared_packets = sum(shared.values())

    print(f"Left packets:  {left_summary.packet_count}")
    print(f"Right packets: {right_summary.packet_count}")
    print(f"Shared packets by payload hash: {shared_packets}")
    print(f"Only left packets:  {sum(only_left.values())}")
    print(f"Only right packets: {sum(only_right.values())}")

    if only_left or only_right:
        print("Result: mismatch")
        return 1

    print("Result: match")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compare packet payloads between two captures (.pcap/.pcapng).",
    )
    parser.add_argument("--left", required=True, type=Path)
    parser.add_argument("--right", required=True, type=Path)
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    raise SystemExit(compare(args.left, args.right))
