"""
find_diff.py — finds which field causes the integrity hash mismatch
Run: /c/Users/User/AppData/Local/Programs/Python/Python310/python find_diff.py passport.json
"""
import json, hashlib, sys, rfc8785

with open(sys.argv[1]) as f:
    p = json.load(f)

stored = p.get("integrity_hash", "")
check = {k:v for k,v in p.items() if k not in ("integrity_hash","signature")}

print(f"Stored:   {stored[:32]}...")
print(f"Fields in check: {len(check)}")
print()

# Try removing one field at a time to find which one changes the hash
baseline = hashlib.sha256(rfc8785.dumps(check)).hexdigest()
print(f"Full recompute: {baseline[:32]}...")
print(f"Stored:         {stored[:32]}...")
print(f"Match: {baseline == stored}")
print()

# Check each field value type
print("=== Field types ===")
for k, v in check.items():
    t = type(v).__name__
    if t not in ("str", "dict", "list", "NoneType", "bool"):
        print(f"  UNUSUAL: {k}: {t} = {repr(v)[:50]}")

# Try compact JSON
compact = json.dumps(check, sort_keys=True, separators=(',',':')).encode()
compact_hash = hashlib.sha256(compact).hexdigest()
print(f"\nCompact JSON hash: {compact_hash[:32]}...")
print(f"Compact matches stored: {compact_hash == stored}")

# Try with default=str round-trip
rt = json.loads(json.dumps(check, default=str))
rt_hash = hashlib.sha256(rfc8785.dumps(rt)).hexdigest()
print(f"rfc8785 after str round-trip: {rt_hash[:32]}...")
print(f"Matches stored: {rt_hash == stored}")
