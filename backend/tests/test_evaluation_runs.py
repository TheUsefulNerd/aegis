"""Past compliance checks are preserved exactly: a later re-check (with a
newly taught pattern) changes the device's live findings but never an
earlier run, and an earlier report can be re-issued from what was stored."""
import io

from app import signing

CFG = "version 17.3\nhostname r9\nline vty 0 4\n transport input ssh\norgpolicy-tag SEC-BASELINE-77 apply\n"


def _ingest(client):
    return client.post("/ingest", files={"file": ("r9.txt", io.BytesIO(CFG.encode()), "text/plain")}).json()


def test_old_run_survives_a_later_recheck(client, tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_SIGNING_KEY", str(tmp_path / "k.pem"))
    monkeypatch.setattr(signing, "_key", None)
    body = _ingest(client)
    first = client.post(f"/configs/{body['config_id']}/evaluate").json()
    before = {f["rule_id"]: f["result"] for f in first["findings"]}
    assert before["CIS-2.2.1"] != "PASS"

    # A reviewer teaches the unknown line; the same config is re-checked.
    item = next(i for i in client.get("/review-queue").json() if i["raw_unit"] == "orgpolicy-tag SEC-BASELINE-77 apply")
    client.post(f"/review-queue/{item['id']}/confirm",
                json={"canonical_field": "AU.logging_enabled", "value": True, "reviewer_id": "lead"})
    body2 = _ingest(client)
    second = client.post(f"/configs/{body2['config_id']}/evaluate").json()
    assert {f["rule_id"]: f["result"] for f in second["findings"]}["CIS-2.2.1"] == "PASS"

    old = client.get(f"/runs/{first['run_id']}").json()
    assert {f["rule_id"]: f["result"] for f in old["findings"]} == before
    assert old["integrity"] == first["integrity"]
    assert client.post("/attestations/verify", json=old["attestation"]).json()["valid"] is True

    pdf = client.get(f"/runs/{first['run_id']}/report.pdf")
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF" and pdf.headers["X-AEGIS-Run"] == first["run_id"]


def test_runs_are_listed_newest_first_and_reports_are_recorded(client):
    body = _ingest(client)
    client.post(f"/configs/{body['config_id']}/evaluate")
    r = client.get(f"/configs/{body['config_id']}/report.pdf")
    runs = client.get(f"/devices/{body['device_id']}/runs").json()
    assert [x["trigger"] for x in runs] == ["report", "evaluate"]
    assert runs[0]["run_id"] == r.headers["X-AEGIS-Run"] and all(x["signed"] for x in runs)
    assert client.get("/runs/nope").status_code == 404
