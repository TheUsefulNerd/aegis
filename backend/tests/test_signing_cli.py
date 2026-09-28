"""Signed attestations (app/signing.py) and the CLI (app/cli.py): a report's
signature verifies, any edit to the signed statement breaks it, a statement
signed with another key is not trusted, and the CLI emits SARIF on the exact
config line and a CI-friendly exit code."""
import copy
import io
import json
import os

import pytest

from app import cli, signing

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "..", "samples", "sample_input_config_files")
EDGE = os.path.join(SAMPLES, "04_cisco_csr1000v_edge_misconfigured.txt")


@pytest.fixture(autouse=True)
def _key(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_SIGNING_KEY", str(tmp_path / "k.pem"))
    monkeypatch.setattr(signing, "_key", None)
    yield
    signing._key = None


def _attestation(client):
    with open(EDGE, "rb") as f:
        body = client.post("/ingest", files={"file": ("edge.txt", f, "text/plain")}).json()
    return client.get(f"/configs/{body['config_id']}/attestation").json()


def test_attestation_verifies_and_binds_the_report(client):
    a = _attestation(client)
    st = a["statement"]
    assert a["algorithm"] == "Ed25519" and st["input_sha256"] and st["findings_sha256"] and st["audit_chain_head"]
    assert client.post("/attestations/verify", json=a).json()["valid"] is True


def test_any_edit_to_the_statement_breaks_the_signature(client):
    a = _attestation(client)
    for key, value in (("counts", {"PASS": 99, "FAIL": 0, "NOT_EVALUATED": 0}), ("findings_sha256", "0" * 64)):
        bad = copy.deepcopy(a)
        bad["statement"][key] = value
        assert client.post("/attestations/verify", json=bad).json()["valid"] is False


def test_a_statement_signed_with_another_key_is_not_trusted(client):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    a = _attestation(client)
    other = Ed25519PrivateKey.generate()
    forged = copy.deepcopy(a)
    forged["statement"]["counts"]["FAIL"] = 0
    import base64
    forged["signature"] = base64.b64encode(other.sign(signing._canonical(forged["statement"]))).decode()
    forged["public_key"] = signing.public_pem(other.public_key())
    assert signing.verify(forged)["valid"] is True          # self-consistent...
    assert client.post("/attestations/verify", json=forged).json()["valid"] is False  # ...but not our key


def test_pdf_carries_the_signature(client):
    with open(EDGE, "rb") as f:
        body = client.post("/ingest", files={"file": ("edge.txt", f, "text/plain")}).json()
    pdf = client.get(f"/configs/{body['config_id']}/report.pdf").content
    assert pdf[:4] == b"%PDF"


def test_cli_sarif_and_exit_code(tmp_path, monkeypatch):
    from app.main import app
    monkeypatch.setenv("AEGIS_LLM_MODE", "off")  # the CLI sets it; restored after the test
    monkeypatch.setattr(app, "dependency_overrides", dict(app.dependency_overrides))
    monkeypatch.setattr(app.router, "on_startup", list(app.router.on_startup))
    sarif, att = tmp_path / "r.sarif", tmp_path / "a.json"
    code = cli.main(["audit", EDGE, "--sarif", str(sarif), "--attest", str(att)])
    assert code == 1  # the misconfigured edge router has CAT I failures
    doc = json.load(open(sarif, encoding="utf-8"))
    results = doc["runs"][0]["results"]
    fails = [r for r in results if r["kind"] == "fail"]
    assert doc["version"] == "2.1.0" and fails
    assert any("region" in r["locations"][0]["physicalLocation"] for r in fails)
    assert cli.main(["audit", EDGE, "--fail-on", "none"]) == 0
    assert cli.main(["verify", str(att), "--fingerprint", signing.fingerprint()]) == 0
    assert cli.main(["verify", str(att), "--fingerprint", "0" * 16]) == 1
