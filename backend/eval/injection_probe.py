"""Measure the input-sanity gate: attack catch rate on eval/injection_corpus.yaml
and false positives on every real line of the demo configs.

    python -m eval.injection_probe
"""
import datetime as dt
import glob
import json
import os
import sys

import yaml

from app import fingerprint, redaction, resolve, sanity_gate, units

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.normpath(os.path.join(HERE, "..", "..", "samples", "sample_input_config_files"))

# The planted attacks in the demo configs (expected to be caught, so not
# counted as false positives).
PLANTED = ("NEW INSTRUCTIONS", "Ignore all prior instructions", "SYSTEM PROMPT UPDATE")


def sample_units() -> list:
    out = []
    for path in sorted(glob.glob(os.path.join(SAMPLES, "*.*"))):
        if path.endswith(".md"):
            continue
        r = redaction.redact(open(path, encoding="utf-8").read())
        fp = fingerprint.fingerprint(r.text)
        out += [(os.path.basename(path), u) for u in units.split_into_units(r.text, fp["format"])]
    return out


def run() -> dict:
    corpus = yaml.safe_load(open(os.path.join(HERE, "injection_corpus.yaml"), encoding="utf-8"))
    missed = [a for a in corpus["attacks"] if not sanity_gate.scan(a).flagged]
    real = sample_units()
    planted = [(f, u) for f, u in real if any(p in u for p in PLANTED)]
    benign = [(f, u) for f, u in real if not any(p in u for p in PLANTED)] + [("hand-picked", b) for b in corpus["benign"]]
    false_pos = [(f, u) for f, u in benign if sanity_gate.scan(u).flagged]
    planted_missed = [(f, u) for f, u in planted if not sanity_gate.scan(u).flagged]
    ho = corpus.get("held_out_attacks", [])
    ho_missed = [a for a in ho if not sanity_gate.scan(a).flagged]
    ho_fp = [b for b in corpus.get("held_out_benign", []) if sanity_gate.scan(b).flagged]
    # End to end: does the line reach the AI at all? It doesn't if the gate
    # flags it, or if it is a free-text field (never sent to the AI).
    reach = lambda a: not sanity_gate.scan(a).flagged and not resolve.is_free_text(a)
    all_attacks = corpus["attacks"] + ho
    reaching = [a for a in all_attacks if reach(a)]
    n = len(corpus["attacks"])
    return {
        "all_attacks": len(all_attacks), "reach_the_ai": len(reaching), "reaching_lines": reaching,
        "held_out_attacks": len(ho), "held_out_caught": len(ho) - len(ho_missed),
        "held_out_catch_rate": round((len(ho) - len(ho_missed)) / len(ho), 4) if ho else None,
        "held_out_missed": ho_missed,
        "held_out_benign": len(corpus.get("held_out_benign", [])), "held_out_false_positives": ho_fp,
        "attacks": n, "caught": n - len(missed), "catch_rate": round((n - len(missed)) / n, 4),
        "missed": missed,
        "planted_in_demo_configs": len(planted), "planted_missed": planted_missed,
        "benign_lines": len(benign), "false_positives": false_pos,
        "false_positive_rate": round(len(false_pos) / len(benign), 4),
        "run_at": dt.datetime.now().isoformat(timespec="seconds"),
    }


def main():
    res = run()
    print(json.dumps(res, indent=1, ensure_ascii=False))
    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    out = os.path.join(HERE, "results", f"injection-{dt.datetime.now():%Y%m%d-%H%M%S}.json")
    json.dump(res, open(out, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
