"""Verdict-level ground truth in CI: every hand-labelled verdict in
eval/verdict_labels.yaml, run through the real pipeline with the AI off.
A wrong verdict (false PASS or false FAIL) fails the build; "unknown" is
allowed, since it is what AEGIS reports when a config is silent."""
import os

import yaml

EVAL = os.path.join(os.path.dirname(__file__), "..", "eval")
LABELS = os.path.join(EVAL, "verdict_labels.yaml")


def _run(client, labels_file):
    labels = yaml.safe_load(open(labels_file, encoding="utf-8"))
    samples = os.path.normpath(os.path.join(os.path.dirname(labels_file), labels["samples_dir"]))
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
    return wrong, decided, total


def test_no_wrong_verdicts_on_heldout_real_configs(client):
    """The held-out public configs (labels committed before the first run).
    Undecided is allowed; a wrong verdict is not."""
    wrong, decided, total = _run(client, os.path.join(EVAL, "heldout_labels.yaml"))
    assert wrong == []
    assert decided >= 41, f"held-out decided verdicts fell to {decided}/{total}"


def test_no_wrong_verdicts_on_labelled_configs(client):
    wrong, decided, total = _run(client, LABELS)
    assert wrong == []
    assert decided / total >= 0.95, f"deterministic coverage fell to {decided}/{total}"
