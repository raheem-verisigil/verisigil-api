import re

with open("main.py", "r", encoding="utf-8") as f:
    content = f.read()

# Functions to stub
functions = [
    ("adversarial_envelope_attacks", "GATE_4_ENVELOPE"),
    ("adversarial_uncertainty_attacks", "GATE_5_UNCERTAINTY"),
    ("adversarial_actuator_paths", "GATE_6_ACTUATOR_PATHS"),
]

for func_name, gate_label in functions:
    start_marker = f"async def {func_name}("
    start_idx = content.find(start_marker)
    if start_idx == -1:
        print(f"Could not find {func_name}")
        continue

    # Find next @app. decorator
    match = re.search(r'\n@app\.(post|get|put|delete|patch)\(', content[start_idx:])
    if match:
        end_idx = start_idx + match.start()
    else:
        end_idx = len(content)

    stub_func = f'''async def {func_name}(
    req: dict,
    x_api_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
):
    """
    {gate_label} stub.
    """
    from datetime import datetime, timezone
    require_api_key(x_api_key, authorization)
    return {{
        "schema": f"VGS-{gate_label}-1.0",
        "gate": "{gate_label}",
        "status": "NOT_TESTABLE",
        "note": "Stubbed pending full implementation",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }}


'''

    content = content[:start_idx] + stub_func + content[end_idx:]
    print(f"Stubbed {func_name}")

with open("main.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Done stubbing gates 4, 5, 6")
