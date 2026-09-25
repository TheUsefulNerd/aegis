"""Score the live Tier-2 classifier against the golden set.

    cd backend && python -m eval.run_eval            # real LLM calls (needs .env keys)
    cd backend && python -m eval.run_eval --batch    # same set through classify_batch (production path)

Makes one real Groq/Gemini call per item - run it deliberately, not in CI.
Reports the numbers architecture-document.md §9 asks for, with the one that
matters most for a compliance tool first:

- wrong-accept rate: the classifier was confident enough to be auto-accepted
  (>= 0.6, the same threshold resolve.py uses) AND was wrong. These are the
  dangerous errors - a wrong mapping that silently feeds a verdict.
- routed-to-human rate: rejected / low-confidence / UNKNOWN on a real
  security setting. Safe (a human sees it) but costs coverage.
- precision on accepted items, recall over security-relevant items, and
  negatives correctly declined.

Results are written to eval/results/<timestamp>.json alongside the model
and prompt versions that produced them, so a number is always traceable.
"""
import datetime as dt
import json
import os
import sys
import time

import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import llm_client  # noqa: E402

ACCEPT_THRESHOLD = 0.6  # keep in sync with resolve.py
HERE = os.path.dirname(os.path.abspath(__file__))


def _value_ok(expected, got) -> bool:
    if isinstance(expected, bool) or isinstance(got, bool):
        return expected is got
    if isinstance(expected, (int, float)) and isinstance(got, (int, float)):
        return float(expected) == float(got)
    return str(expected).strip().lower() == str(got).strip().lower()


def score(item: dict, cand) -> dict:
    expected_field = item["field"]
    got_field = cand.canonical_field if cand else None
    accepted = bool(cand) and cand.canonical_field != "UNKNOWN" and cand.confidence >= ACCEPT_THRESHOLD
    field_ok = got_field == expected_field
    value_ok = True
    if accepted and field_ok and "value" in item:
        value_ok = _value_ok(item["value"], cand.value)
    correct = field_ok and value_ok
    if expected_field == "UNKNOWN":
        outcome = "wrong_accept" if accepted else "correct_decline"
    elif accepted:
        outcome = "correct_accept" if correct else "wrong_accept"
    else:
        outcome = "routed_to_human"
    return {
        "id": item["id"], "unit": item["unit"], "expected": expected_field, "expected_value": item.get("value"),
        "got": got_field, "got_value": cand.value if cand else None,
        "confidence": cand.confidence if cand else None, "provider": cand.provider if cand else None,
        "outcome": outcome,
    }


def main():
    with open(os.path.join(HERE, "golden_set.yaml"), encoding="utf-8") as f:
        items = yaml.safe_load(f)["items"]
    batch = "--batch" in sys.argv
    rows = []
    if batch:
        t0 = time.time()
        cands = llm_client.classify_batch([it["unit"] for it in items])
        elapsed = round(time.time() - t0, 1)
    else:
        cands = []
        for item in items:
            cands.append(llm_client.classify(item["unit"]))
            time.sleep(1.0)  # stay polite to free-tier rate limits
    for item, cand in zip(items, cands):
        rows.append(score(item, cand))
        print(f"{rows[-1]['outcome']:16} {item['id']:9} {item['unit'][:55]!r} -> {rows[-1]['got']} {rows[-1]['got_value']!r}")

    pos = [r for r in rows if r["expected"] != "UNKNOWN"]
    neg = [r for r in rows if r["expected"] == "UNKNOWN"]
    accepted = [r for r in rows if r["outcome"] in ("correct_accept", "wrong_accept")]
    n = lambda o, rs=rows: sum(r["outcome"] == o for r in rs)  # noqa: E731
    summary = {
        "items": len(rows), "security_settings": len(pos), "negatives": len(neg),
        "correct_accept": n("correct_accept"), "wrong_accept": n("wrong_accept"),
        "routed_to_human": n("routed_to_human"), "correct_decline": n("correct_decline"),
        "wrong_accept_rate": round(n("wrong_accept") / len(rows), 3),
        "precision_on_accepted": round(n("correct_accept") / len(accepted), 3) if accepted else None,
        "recall_security_settings": round(n("correct_accept", pos) / len(pos), 3) if pos else None,
        "routed_to_human_rate": round(n("routed_to_human", pos) / len(pos), 3) if pos else None,
        "negatives_declined": round(n("correct_decline", neg) / len(neg), 3) if neg else None,
        "providers": sorted({r["provider"] for r in rows if r["provider"]}),
        "groq_model": llm_client.GROQ_MODEL, "gemini_model": llm_client.GEMINI_MODEL,
        "mode": "batch" if batch else "single",
        "prompt_version": llm_client.BATCH_PROMPT_VERSION if batch else llm_client.PROMPT_VERSION,
        "seconds": elapsed if batch else None,
        "run_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
    }
    print(json.dumps(summary, indent=2))
    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    with open(os.path.join(HERE, "results", f"{stamp}.json"), "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "rows": rows}, f, indent=2)


if __name__ == "__main__":
    main()
