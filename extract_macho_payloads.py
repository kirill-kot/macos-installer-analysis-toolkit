#!/usr/bin/env python3
import re, os, sys

if len(sys.argv) != 2:
    print("Usage: python3 extract_macho_payloads.py <Mach-O binary>")
    sys.exit(1)

bin_path = sys.argv[1]
out_dir = "macho_candidates"
os.makedirs(out_dir, exist_ok=True)

with open(bin_path, "rb") as f:
    data = f.read()

# 1. Printable строки >= 20 символов
printables = re.findall(rb'[\x20-\x7E]{20,}', data)
with open(os.path.join(out_dir, "printable_strings.txt"), "wb") as f:
    for s in printables:
        f.write(s + b"\n")

# 2. Candidate Base64 блоки >= 40 символов
b64_candidates = re.findall(rb'[A-Za-z0-9+/=]{40,}', data)
for i, b in enumerate(b64_candidates):
    out_file = os.path.join(out_dir, f"candidate_{i}.b64")
    with open(out_file, "wb") as f:
        f.write(b + b"\n")

print(f"Extraction done! Printable strings -> {out_dir}/printable_strings.txt")
print(f"{len(b64_candidates)} base64 candidates saved in {out_dir}/candidate_*.b64")

