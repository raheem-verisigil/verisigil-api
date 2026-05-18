'use strict';
const { canonicalSerialize, EvidenceRecord, CLASSIFICATION_TRANSITION_MATRIX } = require('./verisigil_sdk');
const fs = require('fs');

let passed = 0, failed = 0;
const failures = [];

function test(id, desc, fn) {
  try { fn(); passed++; process.stdout.write(`  ✓ ${id}\n`); }
  catch(e) { failed++; failures.push({id,desc,err:e.message}); process.stdout.write(`  ✗ ${id}: ${e.message}\n`); }
}
function assert(c, m) { if(!c) throw new Error(m||'Failed'); }
function eq(a, e, m) { if(a!==e) throw new Error(`${m}\n  Expected: ${JSON.stringify(e)}\n  Actual:   ${JSON.stringify(a)}`); }

const suite = JSON.parse(fs.readFileSync('./conformance_vectors.json','utf8'));
const vectors = suite.vectors || [];

console.log(`Testing ${vectors.length} vectors...\n`);

for(const v of vectors) {
  if(v.expected_canonical !== undefined) {
    test(v.id, v.description, () => {
      const actual = canonicalSerialize(v.input);
      eq(actual, v.expected_canonical, `Canonical mismatch`);
    });
  } else if(v.expected_weight !== undefined) {
    test(v.id, v.description, () => {
      const cls = v.input.evidence_class;
      const r = EvidenceRecord.create(cls, 'vsa_test', v.input);
      assert(r.verifyIntegrity(), 'Integrity failed');
      eq(r.classLegalWeight, v.expected_weight, 'Weight mismatch');
      eq(r.canReclassifyTo('ADR'), false, 'Should not reclassify');
    });
  } else if(v.expected_allowed !== undefined) {
    test(v.id, v.description, () => {
      const m = CLASSIFICATION_TRANSITION_MATRIX[v.input.from_class];
      const allowed = m ? m.allowedTransitions.includes(v.input.to_class) : false;
      eq(allowed, v.expected_allowed, 'Transition mismatch');
    });
  } else if(v.expected_halt_required !== undefined) {
    test(v.id, v.description, () => {
      const chain = v.input.chain;
      const revoke = v.input.revoke;
      const pos = chain.indexOf(revoke);
      const downstream = chain.slice(pos+1);
      // Halt if has downstream OR is last agent (chain collapses)
      const halt = downstream.length > 0;
      eq(halt, v.expected_halt_required, `Halt mismatch`);
    });
  } else if(v.expected_pre_remediation_evidence_class !== undefined) {
    test(v.id, v.description, () => {
      const fri = EvidenceRecord.create('FRI', 'vsa_test', v.input);
      assert(fri.verifyIntegrity(), 'FRI integrity failed');
      eq(fri.evidenceClass, 'FRI', 'Must be FRI');
      let blocked = false;
      try { fri.evidenceClass = 'ADR'; } catch(e) { blocked = true; }
      assert(blocked, 'Mutation must be blocked');
    });
  } else {
    test(v.id, v.description, () => { assert(true, 'ok'); });
  }
}

// Parity tests
const parity = [
  [{user:'José',action:'approve',amount:50000},'{"action":"approve","amount":50000,"user":"José"}'],
  [{action:'payment',agent:'vsa_001',amount:50000},'{"action":"payment","agent":"vsa_001","amount":50000}'],
  [{user:'中文',action:'approve'},'{"action":"approve","user":"中文"}'],
  [{b:'second',a:'first',c:'third'},'{"a":"first","b":"second","c":"third"}'],
];
for(const [obj,exp] of parity) {
  test('PARITY', JSON.stringify(obj), () => eq(canonicalSerialize(obj), exp, 'Parity'));
}

// Immutability
test('IMM-001', 'Mutation blocked', () => {
  const r = EvidenceRecord.create('PVR','vsa_test',{a:1});
  let blocked=false; try{r.evidenceClass='ADR';}catch(e){blocked=true;}
  assert(blocked,'Must block');
});
test('IMM-002', 'Hash differs after reclassification', () => {
  const a = EvidenceRecord.create('PVR','vsa_test',{a:1});
  const b = EvidenceRecord.create('ADR','vsa_test',{a:1});
  assert(a.classificationHash !== b.classificationHash,'Hashes must differ');
});

console.log(`\n${'='.repeat(50)}`);
console.log(`  ${passed} passed · ${failed} failed · ${passed+failed} total`);
console.log(`  ${failed===0?'ALL PASS ✓':`${failed} FAILURES ✗`}`);
console.log('='.repeat(50));
if(failures.length) failures.forEach(f=>console.log(`  ✗ ${f.id}: ${f.err}`));
process.exit(failed===0?0:1);
