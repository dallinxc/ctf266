# Hints — Mutation Station

Read one at a time. Try for 5–10 minutes after each before opening the next.

---

## Hint 1 — Recon

The binary refuses input that doesn't match a specific pattern. Before you fuzz, find out what it wants. Two commands that help:

```bash
file station
strings station | less
```

`strings` shows printable byte sequences embedded in the binary. The error messages are visible there. So is at least one thing that isn't an error message but looks suspiciously deliberate.

Also inspect the sample input. It's the shape of a record that passes. Understand its structure byte-by-byte.

```bash
od -Ax -tx1z -v sample_input.bin
```

---

## Hint 2 — The Protocol

The envelope is three parts, in this order:

1. A magic prefix (8 bytes) — you already saw it in `strings` and at the start of the sample input
2. A 2-byte length field, **little-endian**, telling the parser how many payload bytes follow
3. The payload itself

If any of those three parts is wrong, the parser rejects the record before it ever gets to the interesting code. Your fuzzer needs to keep the envelope valid while varying what's inside.

---

## Hint 3 — Where To Fuzz

The validator is strict about the envelope and relaxed about the payload. That's the asymmetry to exploit. Think about the length field specifically: the field is 2 bytes wide (up to 65,535), but the processor on the other side has a much smaller buffer. What happens if the length field says "large" and the payload is actually large?

Build your harness so it:
- Always writes the correct magic
- Always writes a length field that *honestly* matches the payload size (so the "truncated payload" check passes)
- Varies the payload size and contents each iteration

---

## Hint 4 — Harness Skeleton

If you want a starting point, here's the shape of a Python harness. Fill in the blanks and iterate.

```python
import subprocess, os, random

MAGIC = b'FUZZME\x00\x01'

def build(payload: bytes) -> bytes:
    length = len(payload).to_bytes(2, 'little')
    return MAGIC + length + payload

def run_once():
    size = random.randint(1, 1024)          # vary widely
    payload = os.urandom(size)
    with open('input.bin', 'wb') as f:
        f.write(build(payload))
    r = subprocess.run(['./station', 'input.bin'],
                       capture_output=True, timeout=2)
    return r.returncode, r.stdout, r.stderr

for i in range(10_000):
    rc, out, err = run_once()
    if rc == 0 and b'itc266' in out:
        print("FLAG:", out.decode(errors='replace'))
        break
```

---

## Hint 5 — Why It Works (read only after you've solved it)

The binary installs a signal handler for `SIGSEGV`. When your oversized payload corrupts the saved return address on the stack, the program crashes on function return, the handler fires, and the handler is the thing that prints the flag. The "crash" is the win condition, not the failure state. Classic CAPEC-28 pattern: fuzzing → memory corruption → observable effect.
