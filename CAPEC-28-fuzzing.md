#!/usr/bin/env python3
# Helper: generate C byte array for XOR-obfuscated flag.
flag = "itc266{mut4t10n_st4t10n_cle4red}"
key = 0x5A
enc = bytes([b ^ key for b in flag.encode()])
print("// flag:", flag)
print(f"// length: {len(flag)} bytes")
line = ", ".join(f"0x{b:02X}" for b in enc)
print("static const unsigned char enc_flag[] = {")
# wrap at 12 per line
chunks = [enc[i:i+12] for i in range(0, len(enc), 12)]
for chunk in chunks:
    print("    " + ", ".join(f"0x{b:02X}" for b in chunk) + ",")
print("};")
