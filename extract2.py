#!/usr/bin/env python3
# extract3.py — multi-file safe static extractor for obfuscated shell payloads
# Usage: ./extract3.py file1 [file2 ...]
# Output: payload.b64 (if found) and a report printed to stdout
#
# Safety: DOES NOT execute shell code. Marks unsafe var if RHS contains command-substitution,
# backticks, pipes, redirects, printf \\x, curl/wget, or other suspicious tokens.

import re, sys
from pathlib import Path

if len(sys.argv) < 2:
    sys.exit(2)

files = []
for path_str in sys.argv[1:]:
    p = Path(path_str)
    if not p.exists():
        print("Path not found:", p)
        sys.exit(3)
    if p.is_file():
        files.append(p)
    elif p.is_dir():
        # рекурсивно добавляем все файлы из директории
        for f in p.rglob("*"):
            if f.is_file():
                files.append(f)

if not files:
    print("No files found to process")
    sys.exit(4)

print(f"Found {len(files)} files to scan:")
for f in files:
    print(" ", f)

# read and normalize lines (join continuations)
all_lines = []
for f in files:
    raw = f.read_text().splitlines()
    buf = ""
    for ln in raw:
        if buf:
            buf += "\n" + ln
        else:
            buf = ln
        if buf.rstrip().endswith("\\"):
            buf = buf.rstrip()[:-1]
            continue
        all_lines.append( (f.name, buf) )
        buf = ""
    if buf:
        all_lines.append((f.name, buf))

text = "\n".join(f"{fn}:{ln}" for fn,ln in all_lines)

# regex for assignments (handles VAR=..., VAR+='...', VAR+="...", VAR+=unquoted)
assign_re = re.compile(r'(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(\+?=)\s*(.+?)(?:\s*(?:#.*)?)$')
token_re = re.compile(r'''(?:"([^"]*)"|'([^']*)'|([^\s"']+))''')

unsafe_patterns = [r'\$\(', r'`', r'\|', r'>', r'<', r';', r'&&', r'\|\|', r'\bexec\b', r'\bcat\b', r'\bprintf\b', r'\\x', r'\\u', r'\bcurl\b', r'\bwget\b', r'\bscp\b', r'\bssh\b', r'\bbase64\b.*-d\b.*-o\b']
perl_key_re = re.compile(r'pack\("H\*"\s*,\s*"([0-9a-fA-F]+)"\)')

raw = {}   # name -> list of (rhs, op, filename, lineno)
order = []

# parse lines with file/line context
for idx,(fn,ln) in enumerate(all_lines, start=1):
    m = assign_re.match(ln)
    if m:
        name = m.group(1)
        op = m.group(2)
        rhs = m.group(3).strip()
        raw.setdefault(name, []).append((rhs, op, fn, idx))
        if name not in order:
            order.append(name)

def is_unsafe(rhs):
    for pat in unsafe_patterns:
        if re.search(pat, rhs):
            return True
    if re.search(r'\$\(|`', rhs):
        return True
    return False

def normalize_rhs(rhs):
    parts = []
    for mm in token_re.finditer(rhs):
        if mm.group(1) is not None:
            parts.append(mm.group(1))
        elif mm.group(2) is not None:
            parts.append(mm.group(2))
        else:
            parts.append(mm.group(3))
    return ''.join(parts)

# build initial resolved map, prefer last assignment in file order
resolved = {}
unsafe = set()
orig_contents = {}

for name in order:
    entries = raw.get(name, [])
    # take last assignment (most recent)
    rhs, op, fn, ln = entries[-1]
    orig_contents[name] = (rhs, op, fn, ln)
    if is_unsafe(rhs):
        unsafe.add(name)
        continue
    val = normalize_rhs(rhs)
    if op == '+=' and name in resolved:
        resolved[name] = resolved[name] + val
    else:
        resolved[name] = val

# iterative substitution
varref_re = re.compile(r'\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?')
for _ in range(200):
    changed = False
    for k in list(resolved.keys()):
        v = resolved[k]
        def repl(m):
            vn = m.group(1)
            if vn in resolved:
                return resolved[vn]
            if vn in unsafe:
                unsafe.add(k)
            return m.group(0)
        new = varref_re.sub(repl, v)
        if new != v:
            resolved[k] = new
            changed = True
    if not changed:
        break

# heuristics: find candidates
candidates = []
for k,v in resolved.items():
    if k in unsafe: continue
    L = len(v)
    # base64-like charset check (allow newlines)
    s = re.sub(r'\s+','',v)
    is_base64ish = bool(re.fullmatch(r'[A-Za-z0-9+/=]+', s)) and len(s) > 200
    # also long strings are candidates
    if is_base64ish or L > 800:
        candidates.append((k, L, is_base64ish))

# also find any perl xor keys in files
perl_keys = {}
for fn,ln in all_lines:
    m = perl_key_re.search(ln)
    if m:
        perl_keys[fn] = m.group(1)

# print report
print("=== extract3 report ===")
print(f"Scanned files: {', '.join(str(x) for x in files)}")
print(f"Resolved safe variables: {len(resolved)} ; unsafe vars: {len(unsafe)}")
print()
if perl_keys:
    print("Perl XOR keys found in source (file -> hexkey):")
    for fn,k in perl_keys.items():
        print(f"  {fn} -> {k}")
    print()

if candidates:
    print("Candidate variables (safe) — heuristics (name, len, base64ish):")
    for k,L,base64ish in sorted(candidates, key=lambda x: (-x[1], x[0])):
        rhs,op,fn,ln = orig_contents.get(k, ("(unknown)","?","?","?"))
        print(f"  {k}  len={L}  base64ish={base64ish}  defined_at={fn}:{ln}")
else:
    print("No obvious safe candidate found automatically.")

# fallback: pick the longest safe var
safe_vars = [ (k,len(v)) for k,v in resolved.items() if k not in unsafe ]
if safe_vars:
    longest = max(safe_vars, key=lambda x: x[1])[0]
    print(f"\nLongest safe var: {longest} (len={len(resolved[longest])}) — saving to payload.b64")
    Path('payload.b64').write_text(resolved[longest])
    print("Saved payload.b64")
    sys.exit(0)
else:
    print("\nNo safe variable to write payload.b64. Listing unsafe and unresolved vars:")
    if unsafe:
        print(" Unsafe vars (examples):", ', '.join(list(unsafe)[:30]))
    else:
        print(" (none)")
    sys.exit(4)
