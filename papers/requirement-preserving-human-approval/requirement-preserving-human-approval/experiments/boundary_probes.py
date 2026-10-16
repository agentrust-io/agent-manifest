"""Adversarial boundary probes, separate from repository test suites.

Each probe records what it observed (true or false) instead of asserting, so the
same script can be run against the pinned revisions and against later revisions.
A probe that raises is recorded with its exception type. Output contains no paths.
"""
from pathlib import Path
import sys, json, hashlib, zipfile, io
from copy import deepcopy
from datetime import datetime, timezone

import argparse
p=argparse.ArgumentParser()
p.add_argument('--source-root',type=Path,default=Path.home()/'source')
p.add_argument('--output',type=Path,required=True)
args=p.parse_args()
SRC=args.source_root
OUT=args.output
OUT.mkdir(parents=True,exist_ok=True)
for path in ['agentrust-telemetry/src', 'weight-custody-manifest/python/src', 'agent-manifest/python/src']:
    sys.path.insert(0, str(SRC/path))
from agentrust_telemetry import EvidenceAccumulator, SchemaValidator, TelemetryClient, EvidencePersistenceError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from wcm import BytearrayMemoryRange, run_memory_sweep, verify_memory_sweep, memory_sweep_public_key
from agent_manifest._delegation import HitlApprovalSigner, verify_hitl_approval
from agent_manifest._signing import generate_ed25519, signing_pre_image

results = []
def record(name, value, meaning):
    results.append({'probe': name, 'observed': bool(value), 'meaning': meaning})

def verifies(fn, *a):
    try:
        fn(*a)
        return True
    except Exception:
        return False

v = SchemaValidator(SRC/'agentrust-telemetry/spec/schema')
event = json.loads((SRC/'agentrust-telemetry/conformance/fixtures/valid/policy-decision.json').read_text())
class Log:
    def __init__(self, fail=False): self.calls=0; self.fail=fail
    def emit(self, rec):
        self.calls += 1
        if self.fail: raise RuntimeError('controlled export failure')

a = EvidenceAccumulator(event['run_id'], v)
log = Log(True)
r = TelemetryClient(v, span_resolver=lambda: None, evidence_sink=a, log_emitter=log).emit(event)
record('export_failure_preserves_accepted_event', len(a.snapshot().entries)==1 and len(r.projection_errors)==1, 'Evidence acceptance survives a later operational projection error; memory mode is not durable storage.')

a = EvidenceAccumulator(event['run_id'], v, durable_append=lambda e: False)
log = Log()
try: TelemetryClient(v, span_resolver=lambda: None, evidence_sink=a, log_emitter=log).emit(event)
except EvidencePersistenceError: pass
record('failed_ack_suppresses_projection', log.calls==0 and not a.snapshot().entries, 'No operational projection or local chain advance after callback refusal.')

empty = EvidenceAccumulator('empty-run', v).seal(completeness='complete')
record('empty_complete_declaration_is_accepted', empty.completeness=='complete' and not empty.entries, 'Counterexample: seal does not independently prove capture completeness.')

committed=[]
def ambiguous(entry): committed.append(entry.event_id); raise RuntimeError('ack lost after external commit')
a = EvidenceAccumulator(event['run_id'], v, durable_append=ambiguous)
for _ in range(2):
    try: a.append(event)
    except EvidencePersistenceError: pass
record('external_commit_retry_requires_sink_idempotency', len(committed)==2 and not a.snapshot().entries, 'Counterexample: no cross-store transaction or built-in exactly-once persistence.')

class Alias:
    page_size=64; page_count=4
    def __init__(self): self.p=[bytearray(64) for _ in range(4)]
    def write_page(self,i,x): self.p[0 if i==2 else i][:]=x
    def read_page(self,i): return bytes(self.p[0 if i==2 else i])
key=Ed25519PrivateKey.generate()
sweep=run_memory_sweep(Alias(),challenge_nonce='review-nonce',signing_key=key,sweep_secret=b's'*32)
record('signed_bad_memory_is_authentic_not_acceptable', sweep.aliasing_detected and verify_memory_sweep(sweep,memory_sweep_public_key(key))[0], 'Signature verification authenticates the negative finding. The broker must reject it separately.')
good=run_memory_sweep(BytearrayMemoryRange(64,page_size=64),challenge_nonce='old-challenge',signing_key=key,sweep_secret=b's'*32)
record('signature_verifier_has_no_freshness_input', verify_memory_sweep(good,memory_sweep_public_key(key))[0], 'Broker challenge comparison, not signature verification alone, establishes request freshness.')

kp=generate_ed25519()
scope={'approval_duration_seconds':3600,'risk_tier':'high','action':'review'}
stamp=datetime.now(timezone.utc).isoformat()
signer=HitlApprovalSigner(kp)
approval={'approver_id':'mailto:reviewer@example.test','approved_at':stamp,'approved_scope':scope,'approval_method':'software-key'}
import inspect
method_param='approval_method' in inspect.signature(signer.sign_approval).parameters
extra={'approval_method':approval['approval_method']} if method_param else {}
approval['approval_signature']=signer.sign_approval(manifest_id='review-manifest',approved_at=stamp,approved_scope=scope,approver_id=approval['approver_id'],**extra)
record('approval_signer_accepts_method_parameter', method_param, 'Whether this revision lets the human signer cover approval_method; the probe passes it when available.')
original_ok=verifies(verify_hitl_approval,approval,'review-manifest',kp.public_bytes)
changed=deepcopy(approval); changed['approval_method']='hardware-key'
changed_ok=verifies(verify_hitl_approval,changed,'review-manifest',kp.public_bytes)
record('approval_method_label_is_outside_approval_signature', original_ok and changed_ok, 'True means the unaltered approval verifies and the method-label alteration still verifies (label outside the signature). False with the unaltered approval verifying means the label is bound. Not a full runtime test.')
record('approval_unaltered_verifies', original_ok, 'Control for the previous probe.')
def duration_case(dur):
    sc={'risk_tier':'high','action':'review'}
    if dur is not None: sc['approval_duration_seconds']=dur
    ap={'approver_id':'mailto:reviewer@example.test','approved_at':stamp,'approved_scope':sc,'approval_method':'software-key'}
    ap['approval_signature']=signer.sign_approval(manifest_id='review-manifest',approved_at=stamp,approved_scope=sc,approver_id=ap['approver_id'],**({'approval_method':'software-key'} if method_param else {}))
    return verifies(verify_hitl_approval,ap,'review-manifest',kp.public_bytes)
record('approval_helper_accepts_zero_or_missing_duration', duration_case(0) and duration_case(None), 'True means the single-approval helper accepts approval_duration_seconds of 0 or absent. The integrated verifier applies its own expiry logic.')
base={'manifest_id':'review-manifest','hitl_record':{'required':True,'risk_tier':'high','approvals':[]}}
attached=deepcopy(base); attached['hitl_record']['approvals']=[approval]
weakened=deepcopy(base); weakened['hitl_record']['required']=False
record('requirement_bound_approval_appendable', signing_pre_image(base)==signing_pre_image(attached) and signing_pre_image(base)!=signing_pre_image(weakened), 'Issuer pre-image preserves requirements while normalizing only approvals.')

(OUT/'boundary-probes.json').write_text(json.dumps({'captured_at':datetime.now(timezone.utc).isoformat(timespec='seconds'),'results':results,'limits':'Single-process software probes; no hardware or legal conclusion.'},indent=2)+chr(10),encoding='utf-8',newline=chr(10))
print(json.dumps(results,indent=2))
