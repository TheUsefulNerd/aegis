"""Signed report attestations (Ed25519).

The integrity panel's hashes show what a report was computed from; a
signature shows WHO computed it and that none of it changed since. Each
evaluation yields an attestation - the input file's SHA-256, the rule-set
hash, the findings digest and the head of the human-decision hash chain -
signed with this deployment's Ed25519 key. Anyone holding the public key
(GET /signing/public-key) can verify a report offline:

    python -m app.cli verify attestation.json

Key: AEGIS_SIGNING_KEY names a PEM private key; otherwise one is generated on
first use at backend/aegis_signing_key.pem (gitignored). A production
deployment would keep it in an HSM or KMS; the verification side is the same.
"""
import base64
import datetime as dt
import hashlib
import json
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

_DEFAULT_KEY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "aegis_signing_key.pem")
_key = None


def _key_path() -> str:
    return os.environ.get("AEGIS_SIGNING_KEY") or _DEFAULT_KEY


def private_key() -> Ed25519PrivateKey:
    global _key
    if _key is None:
        path = _key_path()
        if os.path.exists(path):
            _key = serialization.load_pem_private_key(open(path, "rb").read(), password=None)
        else:
            _key = Ed25519PrivateKey.generate()
            with open(path, "wb") as f:
                f.write(_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return _key


def public_pem(key: Ed25519PublicKey = None) -> str:
    key = key or private_key().public_key()
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def fingerprint(pem: str = None) -> str:
    """SHA-256 of the public key, short form - printed on every report."""
    return hashlib.sha256((pem or public_pem()).encode()).hexdigest()[:16]


def _canonical(statement: dict) -> bytes:
    return json.dumps(statement, sort_keys=True, separators=(",", ":"), default=str).encode()


def attest(report_id: str, input_sha256: str, ruleset_sha256: str, findings_sha256: str,
           audit_head: str, counts: dict) -> dict:
    statement = {
        "aegis_attestation": 1, "report_id": report_id, "input_sha256": input_sha256,
        "ruleset_sha256": ruleset_sha256, "findings_sha256": findings_sha256,
        "audit_chain_head": audit_head, "counts": counts,
        "signed_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
    }
    sig = private_key().sign(_canonical(statement))
    return {"statement": statement, "signature": base64.b64encode(sig).decode(),
            "algorithm": "Ed25519", "key_fingerprint": fingerprint(), "public_key": public_pem()}


def verify(attestation: dict, public_key_pem: str = None) -> dict:
    """{"valid": bool, ...}. With no key given, the attestation's own key is
    used - then a caller must also compare key_fingerprint with the one they
    trust, or anyone could sign with their own key."""
    pem = public_key_pem or attestation.get("public_key")
    try:
        key = serialization.load_pem_public_key(pem.encode())
        key.verify(base64.b64decode(attestation["signature"]), _canonical(attestation["statement"]))
    except (InvalidSignature, ValueError, KeyError, TypeError, AttributeError):
        return {"valid": False, "reason": "signature does not match this statement and key"}
    own = os.path.exists(_key_path()) and fingerprint(pem) == fingerprint()
    return {"valid": True, "key_fingerprint": fingerprint(pem), "trusted_key": public_key_pem is not None or own}
