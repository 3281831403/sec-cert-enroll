import copy
import hashlib
import hmac
import json

from enroll.issue import (
    check_challenge,
    enroll_batch,
    issue,
    issue_challenge,
    policy_allows,
    request_digest,
    verify_csr_signature,
)


NOW = 1_700_000_000
TTL = 300
SIGNING_KEY = b"gsb-sec-cert-enroll-signing-key-v1"
SEMANTIC_FIELDS = ("subject", "public_key", "extensions", "validity_days")
POLICY = {
    "allowed_subjects": ["CN=alpha,O=GSB", "CN=beta,O=GSB"],
    "allowed_key_usages": ["digitalSignature", "keyEncipherment"],
    "max_validity_days": 397,
    "challenge_ttl": TTL,
}


def _canonical(csr):
    payload = {field: csr[field] for field in SEMANTIC_FIELDS}
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sign(csr, key=SIGNING_KEY):
    return hmac.new(key, _canonical(csr), hashlib.sha256).hexdigest()


def _csr(
    subject="CN=alpha,O=GSB",
    public_key="pk-alpha-001",
    key_usage=("digitalSignature",),
    validity_days=365,
    signature=None,
):
    csr = {
        "subject": subject,
        "public_key": public_key,
        "extensions": {"key_usage": list(key_usage)},
        "validity_days": validity_days,
    }
    csr["signature"] = _sign(csr) if signature is None else signature
    return csr


def _store():
    return {
        "signing_key": SIGNING_KEY,
        "challenges": {},
        "issued": {},
        "in_progress": {},
        "rejected": {},
        "certificates": {},
        "next_serial": 1000,
    }


def test_self_signature_tamper_is_detected():
    csr = _csr()
    assert verify_csr_signature(csr, SIGNING_KEY) is True

    tampered = copy.deepcopy(csr)
    tampered["subject"] = "CN=attack,O=GSB"
    assert verify_csr_signature(tampered, SIGNING_KEY) is False

    store = _store()
    digest = request_digest(tampered)
    challenge = issue_challenge(store, digest, NOW, TTL)
    result = issue(store, tampered, challenge, NOW, POLICY)
    assert result["status"] == "rejected"
    assert result["reason"] == "signature"
    assert store["issued"] == {}
    assert store["certificates"] == {}


def test_digest_binds_public_key_and_extensions():
    base = _csr(public_key="pk-alpha-001")
    swapped = _csr(public_key="pk-alpha-002")
    changed_usage = _csr(key_usage=("digitalSignature", "keyEncipherment"))

    base_digest = request_digest(base)
    assert base_digest != request_digest(swapped)
    assert base_digest != request_digest(changed_usage)

    re_signed = _csr(public_key="pk-alpha-001")
    re_signed["signature"] = "f" * 64
    assert request_digest(re_signed) == base_digest

    store = _store()
    for csr in (base, swapped):
        digest = request_digest(csr)
        challenge = issue_challenge(store, digest, NOW, TTL)
        outcome = issue(store, csr, challenge, NOW, POLICY)
        assert outcome["status"] == "issued"
    assert len(store["certificates"]) == 2


def test_challenge_is_bound_to_digest_on_server():
    csr_a = _csr(public_key="pk-alpha-001")
    csr_b = _csr(subject="CN=beta,O=GSB", public_key="pk-beta-001")
    store = _store()
    digest_a = request_digest(csr_a)
    digest_b = request_digest(csr_b)
    challenge = issue_challenge(store, digest_a, NOW, TTL)

    assert check_challenge(store, digest_a, challenge, NOW) is True
    assert check_challenge(store, digest_b, challenge, NOW) is False

    forged = dict(challenge)
    forged["digest"] = digest_b
    assert check_challenge(store, digest_b, forged, NOW) is False

    result = issue(store, csr_b, challenge, NOW, POLICY)
    assert result["status"] == "rejected"
    assert result["reason"] == "challenge"
    assert store["issued"] == {}


def test_expired_challenge_is_rejected():
    csr = _csr()
    store = _store()
    digest = request_digest(csr)
    challenge = issue_challenge(store, digest, NOW, 60)

    assert check_challenge(store, digest, challenge, NOW + 59) is True
    assert check_challenge(store, digest, challenge, NOW + 60) is False

    result = issue(store, csr, challenge, NOW + 61, POLICY)
    assert result["status"] == "rejected"
    assert result["reason"] == "challenge"
    assert store["issued"] == {}


def test_policy_rejects_unlisted_key_usage():
    code_signing = _csr(key_usage=("codeSigning",))
    empty_usage = _csr(key_usage=())
    assert policy_allows(code_signing, POLICY) is False
    assert policy_allows(empty_usage, POLICY) is False

    store = _store()
    digest = request_digest(code_signing)
    challenge = issue_challenge(store, digest, NOW, TTL)
    result = issue(store, code_signing, challenge, NOW, POLICY)
    assert result["status"] == "rejected"
    assert result["reason"] == "policy"
    assert store["issued"] == {}


def test_policy_rejects_validity_over_limit():
    long_lived = _csr(validity_days=3650)
    at_limit = _csr(validity_days=397)
    assert policy_allows(long_lived, POLICY) is False
    assert policy_allows(at_limit, POLICY) is True

    store = _store()
    digest = request_digest(long_lived)
    challenge = issue_challenge(store, digest, NOW, TTL)
    result = issue(store, long_lived, challenge, NOW, POLICY)
    assert result["status"] == "rejected"
    assert result["reason"] == "policy"
    assert store["issued"] == {}


def test_in_progress_request_is_not_issued_twice():
    csr = _csr()
    store = _store()
    digest = request_digest(csr)
    store["in_progress"][digest] = {"started_at": NOW}

    challenge = issue_challenge(store, digest, NOW, TTL)
    result = issue(store, csr, challenge, NOW, POLICY)
    assert result["status"] == "in_progress"
    assert result["digest"] == digest
    assert "serial" not in result
    assert digest in store["in_progress"]
    assert store["issued"] == {}
    assert store["certificates"] == {}


def test_rejected_request_cannot_be_revived():
    csr = _csr(validity_days=3650)
    store = _store()
    digest = request_digest(csr)
    strict_policy = dict(POLICY, max_validity_days=397)
    relaxed_policy = dict(POLICY, max_validity_days=3650)

    first_challenge = issue_challenge(store, digest, NOW, TTL)
    first = issue(store, csr, first_challenge, NOW, strict_policy)
    assert first["status"] == "rejected"
    assert first["reason"] == "policy"
    assert digest in store["rejected"]

    second_challenge = issue_challenge(store, digest, NOW + 1, TTL)
    second = issue(store, csr, second_challenge, NOW + 1, relaxed_policy)
    assert second["status"] == "rejected"
    assert second["digest"] == digest
    assert store["issued"] == {}
    assert store["certificates"] == {}


def test_batch_uses_fresh_challenge_per_request():
    store = _store()
    first = _csr(subject="CN=alpha,O=GSB", public_key="pk-alpha-001")
    second = _csr(subject="CN=beta,O=GSB", public_key="pk-beta-001")

    outcome = enroll_batch(
        [
            {"csr": first, "store": store},
            {"csr": second, "store": store},
        ],
        POLICY,
        NOW,
    )
    assert outcome["issued"] == 2
    assert outcome["rejected"] == 0
    assert [item["status"] for item in outcome["results"]] == ["issued", "issued"]
    assert outcome["results"][0]["serial"] != outcome["results"][1]["serial"]
    assert outcome["results"][0]["challenge"] != outcome["results"][1]["challenge"]
    assert len(store["challenges"]) == 2
    assert len(store["certificates"]) == 2

    for item in outcome["results"]:
        challenge = store["challenges"][item["challenge"]]
        assert challenge["digest"] == item["digest"]


def test_issued_record_keeps_request_digest_for_audit():
    csr = _csr()
    store = _store()
    digest = request_digest(csr)
    challenge = issue_challenge(store, digest, NOW, TTL)
    first = issue(store, csr, challenge, NOW, POLICY)
    assert first["status"] == "issued"

    serial = first["serial"]
    assert store["issued"][digest]["digest"] == digest
    assert store["certificates"][serial]["digest"] == digest

    second_challenge = issue_challenge(store, digest, NOW + 1, TTL)
    second = issue(store, csr, second_challenge, NOW + 1, POLICY)
    assert second["status"] == "issued"
    assert second["serial"] == serial
    assert second["replayed"] is True
    assert len(store["certificates"]) == 1


def test_valid_request_is_issued_and_duplicate_is_idempotent():
    csr = _csr()
    store = _store()
    digest = request_digest(csr)

    first_challenge = issue_challenge(store, digest, NOW, TTL)
    first = issue(store, csr, first_challenge, NOW, POLICY)
    assert first["status"] == "issued"
    assert first["serial"] == 1000
    assert first["digest"] == digest
    assert first["replayed"] is False

    second_challenge = issue_challenge(store, digest, NOW + 1, TTL)
    second = issue(store, csr, second_challenge, NOW + 1, POLICY)
    assert second["status"] == "issued"
    assert second["serial"] == first["serial"]
    assert second["replayed"] is True
    assert len(store["certificates"]) == 1

    certificate = store["certificates"][first["serial"]]
    assert certificate["subject"] == "CN=alpha,O=GSB"
    assert certificate["public_key"] == "pk-alpha-001"
    assert certificate["digest"] == digest


def test_self_signature_mismatch_is_rejected():
    csr = _csr(signature="00" * 32)
    store = _store()
    digest = request_digest(csr)
    challenge = issue_challenge(store, digest, NOW, TTL)

    result = issue(store, csr, challenge, NOW, POLICY)
    assert result["status"] == "rejected"
    assert result["reason"] == "signature"
    assert store["issued"] == {}
    assert store["certificates"] == {}


def test_challenge_digest_mismatch_is_rejected():
    csr_a = _csr(public_key="pk-alpha-001")
    csr_b = _csr(subject="CN=beta,O=GSB", public_key="pk-beta-001")
    store = _store()
    challenge = issue_challenge(store, request_digest(csr_a), NOW, TTL)

    result = issue(store, csr_b, challenge, NOW, POLICY)
    assert result["status"] == "rejected"
    assert result["reason"] == "challenge"
    assert store["issued"] == {}
    assert store["certificates"] == {}


def test_policy_denial_does_not_issue():
    csr = _csr(subject="CN=gamma,O=GSB")
    assert policy_allows(csr, POLICY) is False

    store = _store()
    digest = request_digest(csr)
    challenge = issue_challenge(store, digest, NOW, TTL)
    result = issue(store, csr, challenge, NOW, POLICY)
    assert result["status"] == "rejected"
    assert result["reason"] == "policy"
    assert store["issued"] == {}
    assert store["certificates"] == {}


def test_independent_batches_match_individual_issuance():
    csr_a = _csr(subject="CN=alpha,O=GSB", public_key="pk-alpha-001")
    csr_b = _csr(subject="CN=beta,O=GSB", public_key="pk-beta-001")

    individual = []
    for csr in (csr_a, csr_b):
        store = _store()
        challenge = issue_challenge(store, request_digest(csr), NOW, TTL)
        individual.append(issue(store, csr, challenge, NOW, POLICY))

    store_a = _store()
    store_b = _store()
    batch_a = enroll_batch([{"csr": csr_a, "store": store_a}], POLICY, NOW)
    batch_b = enroll_batch([{"csr": csr_b, "store": store_b}], POLICY, NOW)

    assert batch_a["issued"] == 1
    assert batch_b["issued"] == 1
    assert batch_a["results"][0]["serial"] == individual[0]["serial"]
    assert batch_b["results"][0]["serial"] == individual[1]["serial"]
    assert batch_a["results"][0]["digest"] == individual[0]["digest"]
    assert batch_b["results"][0]["digest"] == individual[1]["digest"]

    serial_a = batch_a["results"][0]["serial"]
    serial_b = batch_b["results"][0]["serial"]
    assert store_a["certificates"][serial_a]["subject"] == "CN=alpha,O=GSB"
    assert store_b["certificates"][serial_b]["subject"] == "CN=beta,O=GSB"