from __future__ import annotations

import argparse
import sys
from pathlib import Path

from roomkey.band.live import MissingBandCredentials, load_live_band_client_from_env
from roomkey.demo_scenarios import run_local_demo
from roomkey.live_demo import run_live_band_demo
from roomkey.receipt import ReceiptVerificationError, verify_receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="roomkey")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo")
    demo_sub = demo.add_subparsers(dest="demo_command", required=True)
    local = demo_sub.add_parser("local")
    local.add_argument("--case", required=True)
    local.add_argument("--out", required=True)

    band = sub.add_parser("band")
    band_sub = band.add_subparsers(dest="band_command", required=True)
    smoke = band_sub.add_parser("smoke")
    smoke.add_argument("--room", required=True)
    smoke.add_argument("--out", required=True)
    live_demo = band_sub.add_parser("demo")
    live_demo.add_argument("--room", required=True)
    live_demo.add_argument("--case", required=True)
    live_demo.add_argument("--out", required=True)

    verify = sub.add_parser("verify")
    verify.add_argument("receipt")

    args = parser.parse_args(argv)

    if args.command == "demo" and args.demo_command == "local":
        receipt = run_local_demo(args.case, out=args.out)
        print("PASS_DEMO_PROOF")
        print(f"receipt_sha256={receipt['receipt_sha256']}")
        print(f"out={Path(args.out)}")
        return 0

    if args.command == "verify":
        try:
            receipt = verify_receipt(args.receipt)
        except ReceiptVerificationError as exc:
            print(f"FAIL_RECEIPT {exc}", file=sys.stderr)
            return 1
        print("PASS_DEMO_PROOF")
        print(f"receipt_sha256={receipt['receipt_sha256']}")
        return 0

    if args.command == "band":
        try:
            client = load_live_band_client_from_env()
        except MissingBandCredentials as exc:
            print(f"BAND_LIVE_SKIPPED_MISSING_CREDENTIALS: {exc}", file=sys.stderr)
            return 2
        if args.band_command == "smoke":
            print("BAND_LIVE_ADAPTER_READY")
            if hasattr(client, "redacted_config"):
                print(f"config={client.redacted_config()}")
            return 0
        if args.band_command == "demo":
            try:
                receipt = run_live_band_demo(args.case, room_id=args.room, out=args.out, client=client)
                verify_receipt(args.out)
            except Exception as exc:
                print(f"FAIL_LIVE_BAND_SPEAR {exc}", file=sys.stderr)
                return 1
            print("PASS_LIVE_BAND_SPEAR")
            print(f"receipt_sha256={receipt['receipt_sha256']}")
            print(f"out={Path(args.out)}")
            return 0

    parser.error("unreachable")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
