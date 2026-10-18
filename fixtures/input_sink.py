"""Generic raw echo-off terminal app: durable source receipts, no agent or model."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import select
import sys
import termios
import time
import tty


def run(receipts: Path, *, seconds: float = 120) -> None:
    fd = sys.stdin.fileno()
    original = termios.tcgetattr(fd)
    deadline = time.monotonic() + seconds
    sequence = 0
    received = bytearray()
    with receipts.open("x", buffering=1) as journal:
        def record(kind: str, **values: object) -> None:
            journal.write(json.dumps({"type": kind, "pid": os.getpid(),
                                      "mono_ns": time.monotonic_ns(), **values}) + "\n")
            journal.flush()
        try:
            tty.setraw(fd)
            attributes = termios.tcgetattr(fd)
            echo_off = not bool(attributes[3] & (termios.ECHO | termios.ICANON))
            if not echo_off:
                raise RuntimeError("source sink failed to enter raw echo-off mode")
            record("ready", raw_echo_off=True)
            print("SOURCE-SINK-READY\r", flush=True)
            while time.monotonic() < deadline:
                readable, _, _ = select.select([fd], [], [], min(.25, max(0, deadline - time.monotonic())))
                if readable:
                    data = os.read(fd, 4096)
                    if not data:
                        break
                    received.extend(data)
                    if len(received) > 65536:
                        raise RuntimeError("source input receipt bound exceeded")
                    record("input", hex=data.hex(), cumulative_hex=received.hex())
                    print("SOURCE-RECEIPT-" + received.hex() + "\r", flush=True)
                sequence += 1
                record("heartbeat", sequence=sequence)
                print(f"SOURCE-HEARTBEAT-{sequence}\r", flush=True)
            record("finished")
        finally:
            termios.tcsetattr(fd, termios.TCSANOW, original)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipts", type=Path, required=True)
    parser.add_argument("--seconds", type=float, default=120)
    args = parser.parse_args()
    if not 0 < args.seconds <= 300:
        parser.error("seconds must be within (0, 300]")
    run(args.receipts, seconds=args.seconds)


if __name__ == "__main__":
    main()
