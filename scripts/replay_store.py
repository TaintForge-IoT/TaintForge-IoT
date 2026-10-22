from __future__ import annotations

import argparse
import json
from pathlib import Path

from taintforge_env.capture_importer import import_capture
from taintforge_env.replay_store import (
    ReplayEntryExistsError,
    ReplayStore,
    ReplayStoreError,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage deterministic TaintForge network replay stores"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init")
    init_parser.add_argument("--store", required=True)

    add_parser = subparsers.add_parser("add")
    add_parser.add_argument("--store", required=True)
    add_parser.add_argument("--transport", choices=["tcp", "udp"], required=True)
    add_parser.add_argument("--ip", required=True)
    add_parser.add_argument("--port", type=int, required=True)
    add_parser.add_argument("--request", required=True)
    add_parser.add_argument("--response", required=True)
    add_parser.add_argument("--protocol-hint")
    add_parser.add_argument("--source-run-id")
    add_parser.add_argument("--notes")
    add_parser.add_argument("--delay-ms", type=int, default=0)
    add_parser.add_argument("--keep-open", action="store_true")
    add_parser.add_argument("--replace", action="store_true")

    import_parser = subparsers.add_parser(
        "import-capture",
        help="Import a completed TCP, UDP or DNS capture; print a JSON source receipt",
    )
    import_parser.add_argument("--store", required=True)
    import_parser.add_argument(
        "--session-dir", required=True,
        help="One archived capture directory containing session.json and events.jsonl",
    )
    import_parser.add_argument("--protocol-hint")

    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--store", required=True)

    lookup_parser = subparsers.add_parser("lookup")
    lookup_parser.add_argument("--store", required=True)
    lookup_parser.add_argument("--transport", choices=["tcp", "udp"], required=True)
    lookup_parser.add_argument("--ip", required=True)
    lookup_parser.add_argument("--port", type=int, required=True)
    lookup_parser.add_argument("--request", required=True)
    lookup_parser.add_argument("--protocol-hint")
    lookup_parser.add_argument("--out")

    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--store", required=True)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    store = ReplayStore(args.store)

    try:
        if args.command == "init":
            store.initialize()
            print(f"Replay store initialized: {store.root}")
            return

        if args.command == "add":
            entry = store.add_from_files(
                transport=args.transport,
                remote_ip=args.ip,
                remote_port=args.port,
                request_path=args.request,
                response_path=args.response,
                protocol_hint=args.protocol_hint,
                close_after_send=not args.keep_open,
                delay_ms=args.delay_ms,
                source_run_id=args.source_run_id,
                notes=args.notes,
                replace=args.replace,
            )
            print("Replay entry added")
            print(f"    entry_id: {entry.entry_id}")
            print(
                f"    request:  {entry.request.transport} "
                f"{entry.request.remote_ip}:{entry.request.remote_port}"
            )
            print(
                f"    response: {entry.response.size} bytes "
                f"sha256={entry.response.sha256}"
            )
            return

        if args.command == "list":
            entries = store.load_entries()
            print(f"Replay entries: {len(entries)}")

            for entry in entries:
                print(
                    f"- {entry.entry_id} "
                    f"{entry.request.transport} "
                    f"{entry.request.remote_ip}:{entry.request.remote_port} "
                    f"request={entry.request.payload_size}B "
                    f"response={entry.response.size}B "
                    f"hint={entry.request.protocol_hint}"
                )
            return

        if args.command == "import-capture":
            result = import_capture(args.session_dir, store, protocol_hint=args.protocol_hint)
            print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
            return

        if args.command == "lookup":
            request_bytes = Path(args.request).read_bytes()
            result = store.lookup(
                transport=args.transport,
                remote_ip=args.ip,
                remote_port=args.port,
                request_bytes=request_bytes,
                protocol_hint=args.protocol_hint,
            )

            if not result.hit:
                print("Replay miss")
                print(f"    fingerprint: {result.fingerprint}")
                raise SystemExit(2)

            assert result.entry is not None
            assert result.response_bytes is not None

            print("Replay hit")
            print(f"    entry_id: {result.entry.entry_id}")
            print(f"    response: {len(result.response_bytes)} bytes")

            if args.out:
                out_path = Path(args.out)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_bytes(result.response_bytes)
                print(f"    written:  {out_path}")
            return

        if args.command == "validate":
            result = store.validate()
            print("Replay store is valid")
            print(json.dumps(result, indent=2))
            return

    except ReplayEntryExistsError as exc:
        print(f"Replay entry already exists: {exc}")
        raise SystemExit(3)
    except (ReplayStoreError, OSError) as exc:
        print(f"Replay store error: {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
