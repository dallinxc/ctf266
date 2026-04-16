# Walkthrough: Fuzzing a Tiny C Parser

**Target:** `tinyparse` (source included)
**Time:** ~20 minutes
**Goal:** Use mutation fuzzing to find an input that crashes `tinyparse`, then minimize the crashing input and understand *why* it crashes.

This walkthrough covers the fuzzing fundamentals you'll need for the CTF. It uses a deliberately simple target so the mechanics are unambiguous. The CTF target is meaner.

---

## Step 0 — Environment Check

You need a Linux shell. Kali (native or WSL2), Ubuntu, or Debian will all work.

```bash
gcc --version         # any modern version
python3 --version     # 3.8+
```

If either is missing:
```bash
sudo apt update && sudo apt install -y gcc python3 make
```

## Step 1 — Install radamsa

[Radamsa](https://gitlab.com/akihe/radamsa) is a general-purpose mutation fuzzer. You feed it a sample input, it spits out a mutated version. Dumb, fast, effective for a first pass.

```bash
# Option A: apt (Kali)
sudo apt install -y radamsa

# Option B: build from source (Ubuntu/Debian if apt package is missing)
git clone https://gitlab.com/akihe/radamsa.git
cd radamsa && make && sudo make install && cd ..
```

Verify:
```bash
echo "hello" | radamsa
```
You should see a mutated version of "hello" — possibly corrupted, possibly longer, possibly binary garbage. Run it a few times; the output changes every run.

## Step 2 — Build the Target

```bash
cd 2-walkthrough
make
```

Sanity-check it:
```bash
echo "Dallin" | ./tinyparse
# → Hello, Dallin!
```

Read `tinyparse.c`. It's 25 lines. Note the `strcpy(name, raw)` into a 32-byte buffer with no length check. That's the bug. Fuzzing should find it.

## Step 3 — Create a Seed Corpus

Seeds are known-good inputs. The fuzzer mutates them. Good seeds speed everything up.

```bash
mkdir -p seeds
echo "Dallin" > seeds/1.txt
echo "Alice" > seeds/2.txt
echo "hello world" > seeds/3.txt
```

## Step 4 — Write a Minimal Fuzzing Harness

A "harness" is the glue that repeatedly feeds mutated inputs to the target and watches for crashes. Here's a 15-line bash version — save as `fuzz.sh`:

```bash
#!/usr/bin/env bash
# Simple radamsa-driven fuzzing harness.
mkdir -p crashes
i=0
while true; do
    i=$((i+1))
    # Pick a random seed, mutate it, pipe into target.
    seed=$(ls seeds/ | shuf -n 1)
    mutated=$(radamsa seeds/"$seed")
    echo "$mutated" | ./tinyparse > /dev/null 2>&1
    rc=$?
    # Exit codes >= 128 mean "killed by signal".
    # 139 = 128 + 11 (SIGSEGV).  We care about those.
    if [ "$rc" -ge 128 ]; then
        echo "[+] Iteration $i — crash (exit $rc). Saving."
        echo "$mutated" > "crashes/crash_${i}_rc${rc}.bin"
        break
    fi
    if [ $((i % 500)) -eq 0 ]; then
        echo "[.] $i iterations, no crash yet..."
    fi
done
```

Make it executable and run:
```bash
chmod +x fuzz.sh
./fuzz.sh
```

On a modern laptop this crashes in well under a second — `strcpy` into a 32-byte buffer is trivial to smash with random mutations.

## Step 5 — Inspect the Crash

```bash
ls crashes/
cat crashes/crash_*_rc139.bin | xxd | head
```

You'll see a long run of mostly-random bytes. Anything ≥ ~40 bytes is enough to corrupt the saved return address and trigger `SIGSEGV` on function return.

## Step 6 — Minimize (Optional but Important)

Real crashes come in ugly, 800-byte forms. A minimized input is the shortest input that still crashes. Fast manual minimizer:

```bash
# Binary search on length
python3 - <<'PY'
import subprocess
with open('crashes/' + __import__('os').listdir('crashes')[0], 'rb') as f:
    data = f.read().rstrip(b'\n')
lo, hi = 1, len(data)
while lo < hi:
    mid = (lo + hi) // 2
    candidate = data[:mid]
    r = subprocess.run(['./tinyparse'], input=candidate + b'\n',
                       capture_output=True)
    if r.returncode >= 128:
        hi = mid         # still crashes → shrink
    else:
        lo = mid + 1     # no crash → grow
print("Minimum crashing length:", lo)
PY
```

Expect a number in the 40–50 range. That's the size where the overflow starts overwriting the saved frame pointer / return address on this target.

## Step 7 — Confirm With a Debugger

```bash
gdb --batch -ex "run < crashes/$(ls crashes/ | head -1)" \
            -ex "bt" -ex "info registers rip" ./tinyparse
```

Look at `rip` in the register dump. If it's been overwritten with bytes from your input (e.g. `0x4141414141414141`), you've confirmed classical stack smashing — the exact failure mode CAPEC-28 was designed to surface.

---

## What You Just Did

You practiced **dumb mutation fuzzing**: pick a seed, randomly mutate it, throw it at the target, watch for crashes, minimize the crashing input, confirm the root cause. This is the foundational technique of CAPEC-28. Smart fuzzers and coverage-guided fuzzers (AFL++, libFuzzer) are speedier and find deeper bugs, but they're the same shape.

## What the CTF Adds

`tinyparse` crashes on *any* long input. Real parsers don't. The CTF target has a protocol it validates first — you can't just spam bytes. You have to fuzz the parts of the input that get fuzzed while keeping the parts that get validated *valid*. That's what smart mutation fuzzing looks like in the wild.

Head to `../3-ctf/README.md` when you're ready.
