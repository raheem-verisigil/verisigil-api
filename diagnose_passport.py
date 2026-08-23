#!/usr/bin/env python3
"""Diagnose what canonical form a passport was signed with."""
import sys, json, hashlib

with open(sys.argv[1]) as f:
    passport = json.load(f)

stored = passport.get("integrity_hash", "")
print(f"Schema: {passport.get('schema')}")
print(f"Stored hash: {stored[:32]}...")
print(f"Total fields: {len(passport)}")
print(f"Field names: {list(passport.keys())}")

# What fields go into integrity hash?
check = {k:v for k,v in passport.items() if k not in ("integrity_hash","signature")}
print(f"\nFields in integrity hash ({len(check)}):")
for k in check.keys():
    print(f"  {k}")

# Try rfc8785
try:
    import rfc8785
    h_jcs = hashlib.sha256(rfc8785.dumps(check)).hexdigest()
    print(f"\nrfc8785 hash:   {h_jcs[:32]}...")
    print(f"rfc8785 match:  {h_jcs == stored}")
except ImportError:
    print("rfc8785 not available")

# Try compact JSON
h_compact = hashlib.sha256(
    json.dumps(check, sort_keys=True, separators=(',',':'), ensure_ascii=False).encode()
).hexdigest()
print(f"compact hash:   {h_compact[:32]}...")
print(f"compact match:  {h_compact == stored}")

# Try without domain_prefix field
check2 = {k:v for k,v in passport.items() 
          if k not in ("integrity_hash","signature","domain_prefix")}
try:
    import rfc8785
    h2 = hashlib.sha256(rfc8785.dumps(check2)).hexdigest()
    print(f"\nrfc8785 (no domain_prefix) match: {h2 == stored}")
except:
    pass
h2c = hashlib.sha256(
    json.dumps(check2, sort_keys=True, separators=(',',':'), ensure_ascii=False).encode()
).hexdigest()
print(f"compact (no domain_prefix) match: {h2c == stored}")
