#!/usr/bin/env python3
from __future__ import annotations

import argparse

from taintforge_env.qemu_strace_parser import (
    QemuStraceParserError,
    parse_qemu_strace,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Normalize QEMU user-mode -strace output into "
            "syscall_events.jsonl"
        )
    )
    parser.add_argument("--input", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--target-arch", required=True)
    parser.add_argument("--endpoint-events")
    parser.add_argument("--endpoint-session")
    parser.add_argument("--endpoint-attempt")
    args = parser.parse_args()

    try:
        summary = parse_qemu_strace(
            args.input,
            args.out,
            target_arch=args.target_arch,
            endpoint_events=args.endpoint_events,
            session_id=args.endpoint_session,
            attempt_id=args.endpoint_attempt,
        )
    except QemuStraceParserError as exc:
        print(f"[!] QEMU strace parsing failed: {exc}")
        raise SystemExit(1) from exc

    print("[+] QEMU guest syscalls parsed")
    print(f"[+] events: {summary.get('events_total')}")
    print(f"[+] categories: {summary.get('by_category')}")
    print(f"[+] high risk: {summary.get('high_risk_count')}")


if __name__ == "__main__":
    main()
