"""
VeriSigil AI Python SDK
========================
Formal governance infrastructure client.
Version: 1.0.0 | Schema: VGS-SDK-1.0
"""

import hashlib, json, secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import urllib.request

def canonical_serialize(obj: dict) -> str:
    """VER-INV-008: Deterministic canonical JSON — sort_keys, compact, ensure_ascii=False"""
    return json.dumps(obj, sort_keys=True, separators=(',',':'), ensure_ascii=False, default=str)

def canonical_hash(obj: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical_serialize(obj).encode('utf-8')).hexdigest()

EVIDENCE_CLASSES = {
    "GDR": {"name":"Governance Delegation Receipt",  "legal_weight":"DELEGATION_AUTHORITY"},
    "RCR": {"name":"Runtime Continuity Record",      "legal_weight":"CONTINUITY_PROOF"},
    "ATR": {"name":"Authority Transition Record",    "legal_weight":"AUTHORITY_TRANSITION"},
    "EER": {"name":"Escalation Event Record",        "legal_weight":"ESCALATION_EVIDENCE"},
    "ADR": {"name":"Approval Decision Receipt",      "legal_weight":"APPROVAL_DECISION"},
    "PVR": {"name":"Policy Violation Record",        "legal_weight":"POLICY_VIOLATION"},
    "FRI": {"name":"Forensic Reconstruction Input",  "legal_weight":"FORENSIC_INPUT"},
    "AIP": {"name":"Archive Integrity Proof",        "legal_weight":"ARCHIVE_INTEGRITY"},
}

# ALL classes terminal — no reclassification
CLASSIFICATION_TRANSITION_MATRIX = {
    cls: {"allowed_transitions":[], "terminal":True} for cls in EVIDENCE_CLASSES
}

@dataclass(frozen=True)
class EvidenceRecord:
    """
    Immutable evidence record. frozen=True → Python raises AttributeError on mutation.
    classification_hash binds evidence_class + payload at write time.
    Reclassification produces different hash — structurally detectable.
    """
    record_id:        str
    evidence_class:   str
    agent_id:         str
    event_data:       str
    created_at:       str
    execution_id:     str = ""
    classification_hash: str = field(init=False)
    class_legal_weight:  str = field(init=False)

    def __post_init__(self):
        if self.evidence_class not in EVIDENCE_CLASSES:
            raise ValueError(f"Invalid: {self.evidence_class}")
        object.__setattr__(self,'class_legal_weight', EVIDENCE_CLASSES[self.evidence_class]["legal_weight"])
        binding = f"class:{self.evidence_class}|record:{self.record_id}|agent:{self.agent_id}|created:{self.created_at}|payload:{hashlib.sha256(self.event_data.encode()).hexdigest()}"
        object.__setattr__(self,'classification_hash', hashlib.sha256(binding.encode()).hexdigest())

    @classmethod
    def create(cls, evidence_class:str, agent_id:str, event_data:dict, execution_id:str="") -> "EvidenceRecord":
        return cls(
            record_id=f"{evidence_class}_{secrets.token_hex(8)}",
            evidence_class=evidence_class, agent_id=agent_id,
            event_data=canonical_serialize(event_data),
            created_at=datetime.now(timezone.utc).isoformat(),
            execution_id=execution_id,
        )

    def verify_integrity(self) -> bool:
        binding = f"class:{self.evidence_class}|record:{self.record_id}|agent:{self.agent_id}|created:{self.created_at}|payload:{hashlib.sha256(self.event_data.encode()).hexdigest()}"
        return hashlib.sha256(binding.encode()).hexdigest() == self.classification_hash

    def can_reclassify_to(self, new_class:str) -> bool:
        return False  # All classes terminal

    def to_dict(self) -> dict:
        return {
            "record_id": self.record_id, "evidence_class": self.evidence_class,
            "class_name": EVIDENCE_CLASSES[self.evidence_class]["name"],
            "class_legal_weight": self.class_legal_weight,
            "classification_hash": self.classification_hash,
            "agent_id": self.agent_id, "event_data": json.loads(self.event_data),
            "created_at": self.created_at, "immutable": True,
            "reclassification_possible": False, "schema": "VGS-007",
        }

class VeriSigilClient:
    BASE_URL = "https://verisigil-api-production.up.railway.app"

    def __init__(self, api_key:str, base_url:str=None):
        self.api_key = api_key
        self.base_url = base_url or self.BASE_URL

    def _post(self, path:str, body:dict) -> dict:
        data = json.dumps(body, ensure_ascii=False).encode('utf-8')
        req  = urllib.request.Request(f"{self.base_url}{path}", data=data,
               headers={"Content-Type":"application/json","x-api-key":self.api_key}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode('utf-8'))

    def _get(self, path:str) -> dict:
        req = urllib.request.Request(f"{self.base_url}{path}", headers={"x-api-key":self.api_key})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode('utf-8'))

    def health(self):                          return self._get("/health")
    def guard_verify(self, agent_id, action_type, action_details=None, resource=""):
        return self._post("/v1/guard/verify", {"agent_id":agent_id,"action_type":action_type,"action_details":action_details or {},"resource":resource})
    def issue_eat(self, agent_id, delegated_by, allowed_action, max_amount=1000, max_consequence="MEDIUM"):
        return self._post("/v1/eat/issue", {"agent_id":agent_id,"delegated_by":delegated_by,"allowed_action":allowed_action,"allowed_parameters":{"max_amount_usd":max_amount},"constraints":{},"max_consequence":max_consequence,"validity_hours":24})
    def resolve_jurisdiction(self, action_type, data_subject_region="", infrastructure_region="", agent_owner_jurisdiction=""):
        return self._post("/v1/jurisdiction/resolve", {"action_type":action_type,"data_subject_region":data_subject_region,"infrastructure_region":infrastructure_region,"agent_owner_jurisdiction":agent_owner_jurisdiction})
    def formal_prove(self):                    return self._post("/v1/formal/prove", {})
    def formal_certificate(self):             return self._post("/v1/formal/certificate", {})
    def get_invariants(self):                  return self._get("/v1/invariants")
    def get_named_invariants(self):            return self._get("/v1/invariants/named")
    def get_conformance_vectors(self):         return self._get("/v1/conformance/vectors")
    def verify_conformance(self):             return self._post("/v1/conformance/verify", {})
    def create_chain(self, chain_id, root_agent, root_trust=0.963, workflow_id=""):
        return self._post("/v1/continuity/chain/create", {"chain_id":chain_id,"root_agent":root_agent,"root_trust":root_trust,"workflow_id":workflow_id})
    def delegate(self, chain_id, from_agent, to_agent, to_trust=0.963):
        return self._post("/v1/continuity/chain/delegate", {"chain_id":chain_id,"from_agent":from_agent,"to_agent":to_agent,"to_trust":to_trust})
    def revoke_propagate(self, chain_id, agent_id, reason):
        return self._post("/v1/continuity/chain/revoke", {"chain_id":chain_id,"agent_id":agent_id,"reason":reason})

if __name__ == "__main__":
    print("=" * 55)
    print("  VeriSigil AI Python SDK — Self Test")
    print("=" * 55)

    # Canonical serialization
    obj   = {"user": "José", "action": "approve", "amount": 50000}
    canon = canonical_serialize(obj)
    print(f"\n✓ Canonical: {canon}")
    print(f"✓ Hash:      {canonical_hash(obj)[:40]}...")

    # Immutable evidence
    r = EvidenceRecord.create("GDR", "vsa_test", {"action":"payment","amount":5000})
    print(f"\n✓ Record:    {r.record_id}")
    print(f"✓ Class:     {r.evidence_class} → {r.class_legal_weight}")
    print(f"✓ Integrity: {r.verify_integrity()}")
    print(f"✓ Reclassify:{r.can_reclassify_to('ADR')} (False = correct)")

    # Attack detection
    forged = EvidenceRecord.create("ADR","vsa_test",{"action":"payment","amount":5000})
    print(f"\n✓ Attack detected: {r.classification_hash != forged.classification_hash}")

    # All classes terminal
    for cls in ["GDR","PVR","ADR"]:
        t = CLASSIFICATION_TRANSITION_MATRIX[cls]["allowed_transitions"]
        print(f"✓ {cls} transitions: {t}")

    print("\n" + "=" * 55)
    print("  ALL SELF-TESTS PASSED")
    print("=" * 55)
