# VeriSigil AI — Constitutional Gateway SDK

**Intelligence scales. Legitimacy is verified.**

```bash
pip install verisigil

# First 5 minutes:
python -m verisigil financial-agent
python -m verisigil financial-agent --action transfer_250k
```

```python
from verisigil import VeriSigilConstitutionalClient

vs = VeriSigilConstitutionalClient(api_key="your-key")
passport = vs.issue_passport("credit-scorer", "compliance@bank.com", "langchain")
decision = vs.verify_before_action(passport.agent_id, {"type": "loan_approval", "amount": 50000})
evidence = vs.export_evidence_bundle(decision.execution_id)
```

DOI: [10.5281/zenodo.20451306](https://doi.org/10.5281/zenodo.20451306)
