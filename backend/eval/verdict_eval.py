"""Verdict-level evaluation: run the full pipeline (redaction -> units ->
resolution -> rules) on the labelled demo configs and compare every
labelled verdict with verdict_labels.yaml.

    python -m eval.verdict_eval            # AI off: deterministic path only
    python -m eval.verdict_eval --live     # with the configured AI (cloud/local)

Results are printed and written to eval/results/verdicts-<mode>-<time>.json.
Uses a throwaway SQLite database; never touches backend/sentra.db.
"""
import argparse
import datetime as dt
import json
import os
import sys
import tempfile

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))


def run(live: bool, labels_file: str = "verdict_labels.yaml") -> dict:
    if not live:
        os.environ["AEGIS_LLM_MODE"] = "off"
    tmp = tempfile.mkdtemp(prefix="aegis-eval-")
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from fastapi.testclient import TestClient

    from app import db as db_mod
    from app.main import app
    from app.models import Base
    from app.rules_loader import load_rule_files
    from app.seed_loader import load_seed_kb

    engine = create_engine(f"sqlite:///{os.path.join(tmp, 'eval.db')}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    s = Session()
    load_rule_files(s)
    load_seed_kb(s)
    s.close()

    def _get_db():
        d = Session()
        try:
            yield d
        finally:
            d.close()

    app.dependency_overrides[db_mod.get_db] = _get_db
    app.router.on_startup.clear()  # rules/seeds already loaded above; skip the embedding warm-up
    labels = yaml.safe_load(open(os.path.join(HERE, labels_file), encoding="utf-8"))
    samples = os.path.normpath(os.path.join(HERE, labels["samples_dir"]))
    rows, totals = [], {"labelled": 0, "correct": 0, "false_pass": 0, "false_fail": 0, "undecided": 0}
    with TestClient(app) as client:
        for name, expected in labels["devices"].items():
            with open(os.path.join(samples, name), "rb") as f:
                body = client.post("/ingest", files={"file": (name, f, "text/plain")}).json()
            got = {x["rule_id"]: x for x in client.post(f"/configs/{body['config_id']}/evaluate").json()["findings"]}
            for rule_id, want in expected.items():
                out = got.get(rule_id, {}).get("result", "MISSING")
                kind = ("correct" if out == want else "undecided" if out == "NOT_EVALUATED"
                        else "false_pass" if out == "PASS" else "false_fail")
                totals["labelled"] += 1
                totals[kind] += 1
                rows.append({"device": name, "rule": rule_id, "expected": want, "got": out, "outcome": kind,
                             "source": got.get(rule_id, {}).get("confidence_tier"),
                             "evidence": got.get(rule_id, {}).get("source_lines") if kind != "correct" else None})
    decided = totals["correct"] + totals["false_pass"] + totals["false_fail"]
    summary = {
        **totals,
        "decided": decided,
        "accuracy_when_decided": round(totals["correct"] / decided, 4) if decided else None,
        "coverage": round(decided / totals["labelled"], 4) if totals["labelled"] else None,
        "mode": "live" if live else "ai_off",
        "labels": labels_file,
        "run_at": dt.datetime.now().isoformat(timespec="seconds"),
    }
    return {"summary": summary, "rows": rows}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true", help="use the configured AI provider (real API calls)")
    ap.add_argument("--labels", default="verdict_labels.yaml", help="e.g. heldout_labels.yaml")
    args = ap.parse_args()
    result = run(args.live, args.labels)
    s = result["summary"]
    for r in result["rows"]:
        if r["outcome"] != "correct":
            print(f"  {r['outcome']:10} {r['device'][:34]:34} {r['rule']:28} expected {r['expected']:5} got {r['got']}")
    print(json.dumps(s, indent=1))
    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    tag = os.path.splitext(args.labels)[0]
    out = os.path.join(HERE, "results", f"{tag}-{s['mode']}-{dt.datetime.now():%Y%m%d-%H%M%S}.json")
    json.dump(result, open(out, "w", encoding="utf-8"), indent=1)
    print("wrote", out)
    return 0 if s["false_pass"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
