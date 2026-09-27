"""A reviewer names an unknown vendor in the GUI: its signature is learned,
its taught patterns move out of the shared `unknown` bucket, and the next
device of that vendor reuses them - an unrelated unknown vendor does not."""
import io

ARISTA_1 = ("! device: lab1 (vEOS, EOS-4.15.2.1F)\n! boot system flash:/vEOS-lab.swi\nhostname lab1\n"
            "management api http-commands\n   no shutdown\norgpolicy-tag SEC-BASELINE-77 apply\n")
ARISTA_2 = ("! device: lab2 (vEOS, EOS-4.20.1F)\nhostname lab2\norgpolicy-tag SEC-BASELINE-77 apply\n")
MIKROTIK = ("# RouterOS 7.12\n/system identity set name=mt1\norgpolicy-tag SEC-BASELINE-77 apply\n")


def _ingest(client, name, text):
    res = client.post("/ingest", files={"file": (name, io.BytesIO(text.encode()), "text/plain")})
    assert res.status_code == 200, res.text
    return res.json()


def _teach(client):
    item = next(i for i in client.get("/review-queue").json() if i["raw_unit"] == "orgpolicy-tag SEC-BASELINE-77 apply")
    assert client.post(f"/review-queue/{item['id']}/confirm", json={
        "canonical_field": "AU.logging_enabled", "value": True, "reviewer_id": "lead"}).status_code == 200


def test_name_an_unknown_vendor_and_reuse_its_patterns(client):
    first = _ingest(client, "a1.txt", ARISTA_1)
    assert first["vendor"] == "unknown" and "! device: lab1 (vEOS, EOS-4.15.2.1F)" in first["header_sample"]
    _teach(client)
    res = client.post(f"/devices/{first['device_id']}/vendor", json={"vendor": "arista_eos", "signature": "(vEOS,"})
    assert res.status_code == 200 and res.json()["patterns_moved"] == 1

    second = _ingest(client, "a2.txt", ARISTA_2)
    assert second["vendor"] == "arista_eos"
    assert second["fields"]["AU.logging_enabled"] is True and second["tier_counts"]["tier3_human_confirmed"] == 1

    # An unrelated unknown vendor no longer inherits Arista's taught line.
    other = _ingest(client, "mt.txt", MIKROTIK)
    assert other["vendor"] == "unknown" and "AU.logging_enabled" not in other["fields"]


def test_name_vendor_is_validated(client):
    dev = _ingest(client, "a1.txt", ARISTA_1)["device_id"]
    url = f"/devices/{dev}/vendor"
    assert client.post(url, json={"vendor": "Arista EOS!", "signature": "(vEOS,"}).status_code == 422
    assert client.post(url, json={"vendor": "arista_eos", "signature": "not in this file"}).status_code == 422
    assert client.post(url, json={"vendor": "unknown_x", "signature": "(vEOS,"}).status_code == 422
    assert client.post(url, json={"vendor": "arista_eos", "signature": "(vEOS,"}).status_code == 200
    assert client.post(url, json={"vendor": "arista_eos", "signature": "(vEOS,"}).status_code == 409


def test_a_learned_signature_never_relabels_a_known_vendor(client):
    dev = _ingest(client, "a1.txt", "hostname lab1\n! device: x (vEOS\nfoo\n")["device_id"]
    assert client.post(f"/devices/{dev}/vendor", json={"vendor": "arista_eos", "signature": "hostname"}).status_code == 200
    cisco = _ingest(client, "c.txt", "version 15.5\nhostname r1\nline vty 0 4\n")
    assert cisco["vendor"] == "cisco_ios"
