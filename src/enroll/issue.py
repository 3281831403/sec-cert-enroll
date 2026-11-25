"""Certificate enrollment core with eight unimplemented stubs.

The exercise is intentionally stateful.  A store is a mapping with these
keys:

    signing_key    bytes used to authenticate every CSR
    challenges     mapping nonce to challenge record
    issued         mapping request digest to issued certificate record
    in_progress    mapping request digest to a reservation record
    rejected       mapping request digest to a permanent rejection record
    certificates   mapping serial number to the same issued record
    next_serial    next integer serial number to allocate

A CSR is a mapping or JSON object with subject, public_key, extensions,
validity_days and signature.  The signature is HMAC-SHA256, expressed as
lowercase hexadecimal, over the canonical UTF-8 JSON encoding of exactly
subject, public_key, extensions and validity_days, using signing_key.
Canonical JSON means sorted object keys, separators comma and colon, and
no extra whitespace.  The request digest is SHA-256 over that same
canonical encoding, also as lowercase hexadecimal, and deliberately
excludes the signature so a re-signed copy of the same request stays
idempotent.
"""

import hashlib
import hmac
import json
import secrets


SEMANTIC_FIELDS = ("subject", "public_key", "extensions", "validity_days")


def parse_csr(csr: dict) -> dict:
    """Parse and normalize a CSR.

    Accept a mapping or a JSON string or bytes object.  Return a mapping
    with subject, public_key, extensions, validity_days and signature.
    extensions must at least contain a key_usage list.  Raise ValueError
    for malformed input.
    """
    if isinstance(csr, (bytes, bytearray)):
        try:
            csr = csr.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("malformed csr encoding") from exc
    if isinstance(csr, str):
        try:
            csr = json.loads(csr)
        except json.JSONDecodeError as exc:
            raise ValueError("malformed csr json") from exc
    if not isinstance(csr, dict):
        raise ValueError("csr must be a JSON object")

    for field in (*SEMANTIC_FIELDS, "signature"):
        if field not in csr:
            raise ValueError("missing csr field: %s" % field)

    subject = csr["subject"]
    if not isinstance(subject, str) or not subject:
        raise ValueError("subject must be a non-empty string")

    public_key = csr["public_key"]
    if not isinstance(public_key, str) or not public_key:
        raise ValueError("public_key must be a non-empty string")

    validity_days = csr["validity_days"]
    if (
        isinstance(validity_days, bool)
        or not isinstance(validity_days, int)
        or validity_days <= 0
    ):
        raise ValueError("validity_days must be a positive integer")

    extensions = csr["extensions"]
    if not isinstance(extensions, dict) or "key_usage" not in extensions:
        raise ValueError("extensions must contain a key_usage list")
    key_usage = extensions["key_usage"]
    if not isinstance(key_usage, list) or not all(
        isinstance(usage, str) for usage in key_usage
    ):
        raise ValueError("key_usage must be a list of strings")

    if not isinstance(csr["signature"], str):
        raise ValueError("signature must be a hexadecimal string")

    return {
        "subject": subject,
        "public_key": public_key,
        "extensions": dict(extensions),
        "validity_days": validity_days,
        "signature": csr["signature"],
    }


def verify_csr_signature(csr: dict, key) -> bool:
    """Return True only when the CSR signature is valid.

    Recompute HMAC-SHA256 over the canonical semantic fields with key
    and compare using hmac.compare_digest.  A malformed or missing
    signature must return False rather than raise.
    """
    try:
        payload = {field: csr[field] for field in SEMANTIC_FIELDS}
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        expected = hmac.new(key, canonical, hashlib.sha256).hexdigest()
        signature = csr["signature"]
        if not isinstance(signature, str):
            return False
        return hmac.compare_digest(expected, signature)
    except (KeyError, TypeError, ValueError):
        return False


def request_digest(csr: dict) -> str:
    """Return the SHA-256 hexadecimal digest of the request.

    The digest covers subject, public_key, extensions and validity_days,
    including the public key, and excludes signature.  It is used both as
    the idempotency key and as the value a challenge is bound to.
    """
    payload = {field: csr[field] for field in SEMANTIC_FIELDS}
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def issue_challenge(store: dict, digest: str, now: int, ttl: int) -> dict:
    """Issue a fresh challenge bound to digest.

    Allocate an unpredictable nonce, set digest, issued_at, expires_at and
    used=False, and register the record in store["challenges"] under the
    nonce.  Return a copy of the record.
    """
    nonce = secrets.token_hex(16)
    while nonce in store["challenges"]:
        nonce = secrets.token_hex(16)
    record = {
        "nonce": nonce,
        "digest": digest,
        "issued_at": now,
        "expires_at": now + ttl,
        "used": False,
    }
    store["challenges"][nonce] = record
    return dict(record)


def check_challenge(store: dict, digest: str, challenge, now: int) -> bool:
    """Return True only for a live challenge bound to digest.

    challenge may be a challenge mapping or a nonce string.  The server
    record must exist, its digest must equal digest, it must not have been
    consumed, and now must be strictly before expires_at.  Do not trust
    digest or expiry fields supplied by the caller.
    """
    if isinstance(challenge, dict):
        nonce = challenge.get("nonce")
    else:
        nonce = challenge
    if not isinstance(nonce, str):
        return False

    record = store["challenges"].get(nonce)
    if record is None:
        return False
    if record.get("digest") != digest:
        return False
    if record.get("used"):
        return False
    if not now < record["expires_at"]:
        return False
    return True


def policy_allows(csr: dict, policy: dict) -> bool:
    """Apply the enrollment policy to a CSR.

    Return True only when the subject is in policy["allowed_subjects"],
    at least one key usage is requested and every usage is listed in
    policy["allowed_key_usages"], and validity_days is between one and
    policy["max_validity_days"] inclusive.
    """
    if csr["subject"] not in policy["allowed_subjects"]:
        return False

    key_usage = csr["extensions"]["key_usage"]
    if not key_usage:
        return False
    if any(usage not in policy["allowed_key_usages"] for usage in key_usage):
        return False

    validity_days = csr["validity_days"]
    if not 1 <= validity_days <= policy["max_validity_days"]:
        return False

    return True


def issue(store: dict, csr: dict, challenge, now: int, policy: dict) -> dict:
    """Issue or reject one CSR exactly once.

    Outcomes are mappings with a status of issued, rejected or
    in_progress.  An issued outcome also carries serial, digest and
    replayed.  A rejected outcome carries digest and reason.  An
    in_progress outcome carries digest.

    The digest is reserved in store["in_progress"] before policy and
    challenge checks, so a concurrent duplicate cannot issue.  A policy
    or challenge rejection is permanent and recorded in
    store["rejected"].  Replaying an issued digest returns the original
    serial with replayed=True.  Successful issuance records digest in
    both store["issued"] and the certificate record, consumes the
    challenge, and clears the in_progress reservation.
    """
    digest = request_digest(csr)

    issued_record = store["issued"].get(digest)
    if issued_record is not None:
        return {
            "status": "issued",
            "serial": issued_record["serial"],
            "digest": digest,
            "replayed": True,
        }

    if digest in store["rejected"]:
        return {
            "status": "rejected",
            "digest": digest,
            "reason": store["rejected"][digest]["reason"],
        }

    if digest in store["in_progress"]:
        return {"status": "in_progress", "digest": digest}

    store["in_progress"][digest] = {"started_at": now}
    try:
        # Defect 1: authenticate the request self-signature before any
        # state change that could issue a certificate.  A bad signature
        # rejects this attempt only and must not poison the reject table.
        if not verify_csr_signature(csr, store["signing_key"]):
            return {"status": "rejected", "digest": digest, "reason": "signature"}

        # Defects 5 and 6: subject whitelist alone is not enough; key
        # usage and the validity ceiling are enforced as well.  A policy
        # denial is permanent.
        if not policy_allows(csr, policy):
            store["rejected"][digest] = {
                "digest": digest,
                "reason": "policy",
                "rejected_at": now,
            }
            return {"status": "rejected", "digest": digest, "reason": "policy"}

        # Defects 3 and 4: the server-side challenge record must be bound
        # to this digest, unconsumed and unexpired.  Caller-supplied
        # digest/expiry fields are never trusted.
        if not check_challenge(store, digest, challenge, now):
            store["rejected"][digest] = {
                "digest": digest,
                "reason": "challenge",
                "rejected_at": now,
            }
            return {
                "status": "rejected",
                "digest": digest,
                "reason": "challenge",
            }

        nonce = challenge["nonce"] if isinstance(challenge, dict) else challenge
        serial = store["next_serial"]
        store["next_serial"] = serial + 1

        # Defect 10: keep the request digest on both the idempotency
        # record and the certificate so duplicate applications audit.
        certificate = {
            "serial": serial,
            "subject": csr["subject"],
            "public_key": csr["public_key"],
            "extensions": csr["extensions"],
            "validity_days": csr["validity_days"],
            "digest": digest,
            "issued_at": now,
        }
        store["certificates"][serial] = certificate
        store["issued"][digest] = certificate
        store["challenges"][nonce]["used"] = True

        return {
            "status": "issued",
            "serial": serial,
            "digest": digest,
            "replayed": False,
        }
    finally:
        store["in_progress"].pop(digest, None)


def enroll_batch(requests, policy: dict, now: int) -> dict:
    """Process a batch without sharing challenges or state across items.

    requests is an iterable of mappings, each containing csr and store.
    The challenge TTL comes from policy["challenge_ttl"] or 300.  For each
    item, parse the CSR, derive its digest, issue a fresh challenge in
    that item's store, call issue, and add the challenge nonce to the
    outcome under the key challenge.  Return a mapping with results,
    issued and rejected.  One item's denial must not stop later items.
    """
    ttl = policy.get("challenge_ttl", 300)
    results = []
    issued_count = 0
    rejected_count = 0

    for item in requests:
        try:
            csr = parse_csr(item["csr"])
            store = item["store"]
            digest = request_digest(csr)
            # Defect 9: every item gets its own freshly issued challenge
            # bound to its own digest; a challenge is never reused.
            challenge_record = issue_challenge(store, digest, now, ttl)
            outcome = issue(store, csr, challenge_record, now, policy)
            outcome["challenge"] = challenge_record["nonce"]
        except ValueError:
            outcome = {
                "status": "rejected",
                "digest": None,
                "reason": "malformed",
                "challenge": None,
            }
        results.append(outcome)
        if outcome["status"] == "issued":
            issued_count += 1
        elif outcome["status"] == "rejected":
            rejected_count += 1

    return {
        "results": results,
        "issued": issued_count,
        "rejected": rejected_count,
    }
