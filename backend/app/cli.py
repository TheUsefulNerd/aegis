"""AEGIS on the command line - for CI/CD pipelines and offline audits.

    python -m app.cli audit router.cfg fw.conf [--sarif out.sarif] [--attest out.json]
                            [--framework CIS,STIG] [--fail-on CAT_I|CAT_II|CAT_III|none] [--live]
    python -m app.cli verify attestation.json [--key public.pem | --fingerprint 1a2b3c...]

`audit` runs the same pipeline as the web app (redaction, sanity gate, tiered
resolution, deterministic rules) on a throwaway database, with the AI off
unless --live. Lines only the AI or a human could resolve are reported as
unknown, never as passes. SARIF 2.1.0 output puts every FAIL (and every
unknown, as "review") on the exact config line, so GitHub code scanning or
any SARIF viewer shows it inline. Exit code 1 when a FAIL at or above
--fail-on (default CAT_I) is found, 0 otherwise.

`verify` checks an attestation's Ed25519 signature offline. Pass the public
key (or its fingerprint) you trust; the key embedded in the file alone
proves nothing about who signed it.
"""
import argparse
import json
import os
import sys
import tempfile

_SEV_RANK = {"CAT_I": 0, "CAT_II": 1, "CAT_III": 2}
_LEVEL = {"CAT_I": "error", "CAT_II": "warning", "CAT_III": "note"}


def _client(live: bool):
    if not live:
        os.environ["AEGIS_LLM_MODE"] = "off"
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from fastapi.testclient import TestClient

    from . import db as db_mod
    from .main import app
    from .models import Base
    from .rules_loader import load_rule_files
    from .seed_loader import load_seed_kb

    tmp = tempfile.mkdtemp(prefix="aegis-cli-")
    engine = create_engine(f"sqlite:///{os.path.join(tmp, 'cli.db')}", connect_args={"check_same_thread": False})
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
    app.router.on_startup.clear()
    return TestClient(app)


def _hits(hits) -> int:
    return sum(h.get("count", 0) for h in hits or [])


def _line_no(lines: list, source: str):
    """1-based line of the config that a finding's evidence came from."""
    probe = (source or "").split("] ", 1)[-1].strip()  # drop an `[ACL]` tag
    if not probe or probe.startswith("("):
        return None
    for n, line in enumerate(lines, 1):
        if line.strip() == probe:
            return n
    for n, line in enumerate(lines, 1):
        if probe in line or (line.strip() and line.strip() in probe and len(line.strip()) > 8):
            return n
    return None


def _sarif(runs: list) -> dict:
    rules, results = {}, []
    for path, text, ev in runs:
        lines = text.splitlines()
        for f in ev["findings"]:
            if f["result"] == "PASS":
                continue
            rules.setdefault(f["rule_id"], {
                "id": f["rule_id"], "name": f["rule_id"],
                "shortDescription": {"text": f["title"]},
                "properties": {"framework": f["framework"], "severity": f["severity"],
                               "standard": f.get("standard_version")},
            })
            src = (f.get("source_lines") or [None])[0]
            n = _line_no(lines, src)
            loc = {"physicalLocation": {"artifactLocation": {"uri": path.replace(os.sep, "/")}}}
            if n:
                loc["physicalLocation"]["region"] = {"startLine": n}
            fail = f["result"] == "FAIL"
            msg = f["title"] + ("" if fail else " - unknown: " + str((f.get("evidence") or {}).get("reason")
                                                                      or "not found in this config"))
            if fail and f.get("remediation"):
                msg += "\nFix:\n" + f["remediation"]
            results.append({
                "ruleId": f["rule_id"], "kind": "fail" if fail else "review",
                "level": _LEVEL.get(f["severity"], "warning") if fail else "none",
                "message": {"text": msg}, "locations": [loc],
                "properties": {"evidence_tier": f.get("confidence_tier"), "source_lines": f.get("source_lines")},
            })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "AEGIS", "informationUri": "https://github.com/TheUsefulNerd/aegis",
                                          "rules": list(rules.values())}},
                      "results": results}]}


def audit(args) -> int:
    client = _client(args.live)
    runs, attestations, worst_fail = [], [], None
    with client:
        for path in args.files:
            raw = open(path, "rb").read()
            body = client.post("/ingest", files={"file": (os.path.basename(path), raw, "text/plain")}).json()
            params = {"framework": args.framework} if args.framework else {}
            ev = client.post(f"/configs/{body['config_id']}/evaluate", params=params).json()
            runs.append((path, raw.decode("utf-8", "replace"), ev))
            if args.attest:
                attestations.append(client.get(f"/configs/{body['config_id']}/attestation", params=params).json())
            c = ev["counts"]
            print(f"{path}: {body['vendor']} ({body['fingerprint_confidence']})  "
                  f"PASS {c['PASS']}  FAIL {c['FAIL']}  unknown {c['NOT_EVALUATED']}  "
                  f"secrets redacted {_hits(body.get('redaction_hits'))}")
            for f in ev["findings"]:
                if f["result"] == "FAIL":
                    print(f"  FAIL {f['severity']:7} {f['rule_id']:26} {f['title'][:70]}")
                    if worst_fail is None or _SEV_RANK.get(f["severity"], 9) < _SEV_RANK.get(worst_fail, 9):
                        worst_fail = f["severity"]
    if args.sarif:
        json.dump(_sarif(runs), open(args.sarif, "w", encoding="utf-8"), indent=1)
        print("wrote", args.sarif)
    if args.attest:
        json.dump(attestations[0] if len(attestations) == 1 else attestations,
                  open(args.attest, "w", encoding="utf-8"), indent=1)
        print("wrote", args.attest)
    if args.fail_on != "none" and worst_fail and _SEV_RANK[worst_fail] <= _SEV_RANK[args.fail_on]:
        return 1
    return 0


def verify(args) -> int:
    from . import signing
    data = json.load(open(args.attestation, encoding="utf-8"))
    items = data if isinstance(data, list) else [data]
    key = open(args.key, encoding="utf-8").read() if args.key else None
    ok = True
    for a in items:
        r = signing.verify(a, key)
        trusted = r.get("valid") and (key is not None or (args.fingerprint and r["key_fingerprint"] == args.fingerprint))
        st = a.get("statement", {})
        print(f"{st.get('report_id')}: signature {'VALID' if r.get('valid') else 'INVALID'}, key "
              f"{r.get('key_fingerprint', '?')} {'(trusted)' if trusted else '(NOT a key you pinned)'}; "
              f"input {str(st.get('input_sha256'))[:16]}, findings {str(st.get('findings_sha256'))[:16]}")
        ok = ok and bool(trusted)
    return 0 if ok else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("audit", help="audit config files")
    a.add_argument("files", nargs="+")
    a.add_argument("--sarif")
    a.add_argument("--attest", help="write the signed attestation(s) to this JSON file")
    a.add_argument("--framework", help="e.g. CIS or CIS,STIG (default: all loaded)")
    a.add_argument("--fail-on", default="CAT_I", choices=["CAT_I", "CAT_II", "CAT_III", "none"])
    a.add_argument("--live", action="store_true", help="use the configured AI provider")
    v = sub.add_parser("verify", help="verify a signed attestation")
    v.add_argument("attestation")
    v.add_argument("--key", help="PEM public key you trust")
    v.add_argument("--fingerprint", help="or the key fingerprint you trust")
    args = ap.parse_args(argv)
    return audit(args) if args.cmd == "audit" else verify(args)


if __name__ == "__main__":
    sys.exit(main())
