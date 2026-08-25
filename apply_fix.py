# apply_fix.py — patches main.py to fix integrity hash computation
# Run: /c/Users/User/AppData/Local/Programs/Python/Python310/python apply_fix.py
import sys

with open('main.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Find the exact pattern in the current repo version
MARKER_START = '    # Compute integrity hash — excludes only integrity_hash and signature'
MARKER_END = '    return payload'

idx_start = content.find(MARKER_START)
if idx_start == -1:
    print("ERROR: Start marker not found")
    print("Searching for alternative...")
    idx_start = content.find('payload["integrity_hash"] = _vcc_hash(')
    if idx_start == -1:
        print("Cannot find integrity hash line")
        sys.exit(1)
    idx_start = content.rfind('\n', 0, idx_start) + 1

# Find the return payload after this point
idx_end = content.find(MARKER_END, idx_start)
if idx_end == -1:
    print("ERROR: End marker not found")
    sys.exit(1)
idx_end += len(MARKER_END)

old_block = content[idx_start:idx_end]
print("Found block to replace:")
print(old_block[:200])
print("...")

new_block = '''    # Compute integrity hash over JSON-safe form — must match jar_verify
    # jar_verify reads JSON; Railway computes hash on Python dict with datetime objects
    # Fix: convert to JSON-safe form first so both sides hash identical bytes
    import json as _json_mod
    _json_safe = _json_mod.loads(_json_mod.dumps(
        {k: v for k, v in payload.items() if k not in ("integrity_hash", "signature")},
        default=str
    ))
    payload["integrity_hash"] = _vcc_hash(_json_safe)

    # Domain-separated signing over JSON-safe form (same reason)
    domain_bytes = b"SIGILMARK-v1" + b"\\x00"
    _sig_safe = _json_mod.loads(_json_mod.dumps(
        {k: v for k, v in payload.items() if k != "signature"},
        default=str
    ))
    payload_bytes = domain_bytes + _vcb_canonical(_sig_safe)
    raw_sig = SIGNING_KEY.sign(payload_bytes).signature
    payload["signature"] = base64.b64encode(raw_sig).decode()
    return payload'''

content = content[:idx_start] + new_block + content[idx_end:]

with open('main.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("\nFIXED — integrity hash now computed over JSON-safe form")
print(f"File length: {len(content.splitlines())} lines")
