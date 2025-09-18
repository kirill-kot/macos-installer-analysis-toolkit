#!/usr/bin/env python3
# extract_dxuc.py
# Безопасно собирает простые переменные из shell-скрипта (без $(...), backticks, pipes, redirect)
# и пытается разрешить DxucLC. Не выполняет shell-код.

import re
import sys
from pathlib import Path

if len(sys.argv) != 2:
    sys.exit(2)

p = Path(sys.argv[1])
if not p.exists():
    print("File not found:", p)
    sys.exit(2)

text = p.read_text(errors='ignore').splitlines()

assign_re = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$')
varref_re = re.compile(r'\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?')
unsafe_tokens = ['$(', '`', '|', '>', '<', ';', '&>', '&&', '||', 'exec ']

# collect raw assignments (last assignment wins)
raw = {}
lines = []
for i, line in enumerate(text, start=1):
    m = assign_re.match(line)
    if not m:
        lines.append((i, line))
        continue
    name, rhs = m.group(1), m.group(2).strip()
    raw[name] = (rhs, i)

# helper to check safety of RHS
def is_safe_rhs(rhs):
    for t in unsafe_tokens:
        if t in rhs:
            return False
    # allow only quotes, letters, digits, $VAR, =, +, -, ., /, :, _, {} and escapes
    # but don't be overly strict — we mainly block obvious command-substitution
    return True

# normalized RHS: remove surrounding quotes if both ends matching quotes
def normalize_rhs(rhs):
    rhs = rhs.strip()
    if (len(rhs) >= 2) and ((rhs[0] == rhs[-1]) and rhs[0] in ("'", '"')):
        return rhs[1:-1]
    # allow multiple quoted + unquoted concat like "a"$B"c"
    parts = []
    # split into tokens: quoted strings or unquoted
    token_re = re.compile(r'''(?:"([^"]*)"|'([^']*)'|([^"'\s]+))''')
    for mm in token_re.finditer(rhs):
        if mm.group(1) is not None:
            parts.append(mm.group(1))
        elif mm.group(2) is not None:
            parts.append(mm.group(2))
        else:
            parts.append(mm.group(3))
    return ''.join(parts)

# build a map of safe resolved values
resolved = {}
unsafe_vars = set()

for name, (rhs, lineno) in raw.items():
    if not is_safe_rhs(rhs):
        unsafe_vars.add(name)
        continue
    resolved[name] = normalize_rhs(rhs)

# iterative resolution of $VARS
for _ in range(50):
    changed = False
    for name in list(resolved.keys()):
        val = resolved[name]
        def repl(m):
            var = m.group(1)
            if var in resolved:
                return resolved[var]
            return m.group(0)  # keep as is
        new = varref_re.sub(repl, val)
        if new != val:
            resolved[name] = new
            changed = True
    if not changed:
        break

# report
target = 'DxucLC'
if target not in resolved:
    print("DxucLC not resolved automatically.")
    # print suspicious lines where DxucLC referenced or assigned
    for name,(rhs,ln) in raw.items():
        if 'DxucLC' in rhs or name=='DxucLC':
            print(f"Line {ln}: {name} = {rhs}")
    print("\nFound variables (safe-resolved):")
    for k in sorted(resolved.keys()):
        print(f"{k} = (len={len(resolved[k])})")
    print("\nUnsafe or skipped variables:", ','.join(sorted(unsafe_vars)) if unsafe_vars else "(none)")
    sys.exit(3)

payload = resolved[target]
out = Path('payload.b64')
out.write_text(payload)
print(f"Saved installer -> {out}  (len={len(payload)})")
print("Preview (first 200 chars):")
print(payload[:200].replace('\n','\\n'))
