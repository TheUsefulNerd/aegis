"""Verdict-level ground truth in CI: every hand-labelled verdict in
eval/verdict_labels.yaml, run through the real pipeline with the AI off.
A wrong verdict (false PASS or false FAIL) fails the build; "unknown" is
allowed, since it is what AEGIS reports when a config is silent."""
import os

import yaml

LABELS = os.path.join(os.path.dirname(__file__), "..", "eval", "verdict_labels.yaml")


def test_no_wrong_verdicts_on_labelled_configs(client):
    labels = yaml.safe_load(open(LABELS, encoding="utf-8"))
    samples = os.path.normpath(os.path.join(os.path.dirname(LABELS), labels["samples_dir"]))
    wrong, decided, total = [], 0, 0
    for name, expected in labels["devices"].items():
        with open(os.path.join(samples, name), "rb") as f:
            body = client.post("/ingest", files={"file": (name, f, "text/plain")}).json()
        got = {x["rule_id"]: x["result"] for x in client.post(f"/configs/{body['config_id']}/evaluate").json()["findings"]}
        for rule_id, want in expected.items():
            total += 1
            out = got.get(rule_id)
            if out in ("PASS", "FAIL"):
                decided += 1
                if out != want:
                    wrong.append((name, rule_id, want, out))
    assert wrong == []
    assert decided / total >= 0.85, f"deterministic coverage fell to {decided}/{total}"
