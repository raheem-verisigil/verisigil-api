with open("main.py", "r", encoding="utf-8") as f:
    content = f.read()

# Find the start of adversarial_transition_attacks
start_marker = "async def adversarial_transition_attacks("
start_idx = content.find(start_marker)
if start_idx == -1:
    raise RuntimeError("Could not find adversarial_transition_attacks")

# Find the next @app. decorator after this function
import re
match = re.search(r'\n@app\.(post|get|put|delete|patch)\(', content[start_idx:])
if match:
    end_idx = start_idx + match.start()
else:
    end_idx = len(content)

# New stub function with explicit imports
stub_func = '''async def adversarial_transition_attacks(
    req: dict,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    """
    Gate 3: Attack TransitionIntegrityRecord.
    Proves "Validity does not automatically survive movement."
    STUB: Full transition attack suite pending VCB engine integration.
    """
    from datetime import datetime, timezone
    require_api_key(x_api_key, authorization)
    return {
        "schema": "VGS-GATE3-TRANSITION-ATTACKS-1.0",
        "gate": "GATE_3",
        "question": "Do transition attacks correctly produce INVALID/ALLOW distinctions?",
        "status": "NOT_TESTABLE",
        "note": "Transition attack suite pending full VCB engine integration — _VCB_FINAL_ENGINE is a stub dict, build_transition_integrity_record not yet implemented",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


'''

new_content = content[:start_idx] + stub_func + content[end_idx:]

with open("main.py", "w", encoding="utf-8") as f:
    f.write(new_content)

print("Stubbed adversarial_transition_attacks (with imports)")
