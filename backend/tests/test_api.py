"""End-to-end through the real FastAPI routes (LLM mocked off, so every
non-Tier-1 line lands in the review queue): ingest -> sanity gate / redaction
visibility -> review with auditor judgment -> teach-once reuse -> vendor-
scoped evaluation -> PDF."""
from conftest import sample_path

DEMO = "sample_input_config_files"


def _ingest(client, name):
    with open(sample_path(DEMO, name), "rb") as f:
        res = client.post("/ingest", files={"file": (name, f, "text/plain")})
    assert res.status_code == 200, res.text
    return res.json()


def test_sanity_gate_hit_is_flagged_and_sorted_first(client):
    body = _ingest(client, "04_cisco_csr1000v_edge_misconfigured.txt")
    assert len(body["sanity_gate_hits"]) == 1
    hit = body["sanity_gate_hits"][0]
    assert "Ignore all prior instructions" in hit["unit"]
    assert hit["reason"].startswith("This text ")

    queue = client.get("/review-queue").json()
    assert queue[0]["flag_type"] == "sanity_gate"
    assert queue[0]["flag_reason"] == hit["reason"]
    assert queue[0]["device_hostname"] == "CSR1"
    assert all(i["flag_type"] is None for i in queue[1:])

    stats = client.get("/stats").json()
    assert stats["sanity_gate_blocked_total"] == 1


def test_redaction_examples_never_contain_the_secret(client):
    body = _ingest(client, "01_cisco_ios_branch_router_hardened.txt")
    examples = body["redaction_examples"]
    assert examples and len({e["type"] for e in examples}) == len(examples)  # one per type
    for e in examples:
        assert f"[REDACTED:{e['type']}]" in e["unit"]
        assert "FAKE" not in e["unit"] and "DEADBEEF" not in e["unit"]
    assert client.get("/stats").json()["redactions_total"] == sum(h["count"] for h in body["redaction_hits"])


def test_teach_once_then_recognized_instantly_with_auditor_judgment(client):
    _ingest(client, "01_cisco_ios_branch_router_hardened.txt")
    queue = client.get("/review-queue").json()
    item = next(i for i in queue if i["raw_unit"] == "orgpolicy-tag SEC-BASELINE-77 apply")

    res = client.post(f"/review-queue/{item['id']}/confirm", json={
        "canonical_field": "AU.logging_enabled", "value": True, "reviewer_id": "test",
        "pattern_type": "exact", "is_security_relevant": True, "reviewer_notes": "org logging baseline",
    })
    assert res.status_code == 200

    body = _ingest(client, "06_cisco_csr1000v_edge_remediated.txt")
    assert body["fields"]["AU.logging_enabled"] is True

    from app.models import KnowledgeBaseEntry, ReviewQueueItem
    from app.db import get_db
    from app.main import app
    db = next(app.dependency_overrides[get_db]())
    entry = db.query(KnowledgeBaseEntry).filter_by(source="tier3_human").one()
    assert entry.is_security_relevant is True and entry.reviewer_notes == "org logging baseline"
    reviewed = db.get(ReviewQueueItem, item["id"])
    assert reviewed.status == "confirmed" and reviewed.is_security_relevant is True


def test_reject_as_not_applicable_records_the_judgment(client):
    _ingest(client, "01_cisco_ios_branch_router_hardened.txt")
    item = client.get("/review-queue").json()[0]
    res = client.post(f"/review-queue/{item['id']}/reject",
                      json={"reviewer_id": "test", "reason": "not_applicable", "reviewer_notes": "cosmetic"})
    assert res.status_code == 200
    from app.models import ReviewQueueItem
    from app.db import get_db
    from app.main import app
    db = next(app.dependency_overrides[get_db]())
    assert db.get(ReviewQueueItem, item["id"]).is_security_relevant is False


def test_evaluation_is_vendor_scoped_and_most_urgent_first(client):
    body = _ingest(client, "04_cisco_csr1000v_edge_misconfigured.txt")
    ev = client.post(f"/configs/{body['config_id']}/evaluate").json()
    ids = [f["rule_id"] for f in ev["findings"]]
    # A Cisco router is never scored against the CIS pfSense benchmark.
    assert not any(i.startswith("CIS-PF-") for i in ids)
    assert any(i.startswith("STIG-") for i in ids) and any(i.startswith("NIST-") for i in ids)

    order = {"FAIL": 0, "NOT_EVALUATED": 1, "PASS": 2}
    results = [order[f["result"]] for f in ev["findings"]]
    assert results == sorted(results)

    # Deterministic (Tier-1 only): the permit-all shadows the deny-23 line.
    acl = next(f for f in ev["findings"] if f["rule_id"] == "CIS-SUPPLEMENT-ACL-TELNET")
    assert acl["result"] == "FAIL"
    assert acl["evidence"]["first_match"] == "access-list 101 permit ip any any"


def test_pfsense_device_gets_pfsense_benchmark_not_cisco(client):
    body = _ingest(client, "02_pfsense_hq_firewall.xml")
    ids = [f["rule_id"] for f in client.post(f"/configs/{body['config_id']}/evaluate").json()["findings"]]
    assert any(i.startswith("CIS-PF-") for i in ids)
    assert not any(i.startswith("STIG-") for i in ids)


def test_pdf_report_renders(client):
    body = _ingest(client, "06_cisco_csr1000v_edge_remediated.txt")
    res = client.get(f"/configs/{body['config_id']}/report.pdf", params={"tz": "Asia/Kolkata"})
    assert res.status_code == 200
    assert res.content.startswith(b"%PDF")


def test_unknown_config_404s(client):
    assert client.post("/configs/does-not-exist/evaluate").status_code == 404
