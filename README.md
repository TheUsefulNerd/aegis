# AEGIS

**A**utomated **E**valuation & **G**overnance for **I**nfrastructure **S**ecurity

[![CI](https://github.com/TheUsefulNerd/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/TheUsefulNerd/aegis/actions/workflows/ci.yml)

An AI-augmented, vendor-agnostic network device compliance engine, built for Smart India Hackathon 2026 under NTRO's problem statement on multi-vendor network configuration compliance.

AEGIS reads a network device's configuration (any vendor, any format: CLI text, brace- or block-structured CLI, XML, JSON), identifies its security-relevant settings through a tiered deterministic → AI → human pipeline, and checks them against **39 rules across all four frameworks the brief names: CIS, NIST SP 800-53, DISA STIG and ISO/IEC 27001** (38 cite a benchmark section; one is an AEGIS supplementary ACL check, labelled as such). When it meets syntax it has never seen, it asks a human once in the review queue and recognizes it instantly on every device afterwards, with no code change and no redeploy. A new vendor is one YAML file.

**At a glance** (all reproducible, see [Measured results](#measured-results)):
- 73 hand-labelled verdicts over 7 configs and 5 vendors: **73 of 73 correct, 0 wrong**, with the AI off or on
- **0 of 52** prompt-injection lines reach the AI; the gate alone catches 32/32 tuned and 12/20 held-out variants with 0 false positives on 416 real config lines
- AI evidence can **fail** a control on its own but never **pass** a CAT I control without a human; a vendor default can fail a rule but never pass one
- Runs **fully offline** (`AEGIS_LLM_MODE=local` with Ollama/vLLM, or `off`); every human decision is **hash-chained** and verifiable

## Submission deliverables (SIH 2026, PS 26155, Team SIX ORIGINS)

| Deliverable | Where |
|---|---|
| Source code + setup instructions | this repository; setup below |
| Architecture document (2 pages) | [`docs/AEGIS-Architecture-2page.pdf`](docs/AEGIS-Architecture-2page.pdf) (source: [`docs/architecture-document-2page.md`](docs/architecture-document-2page.md)) |
| Demo video (1:57) | [`docs/AEGIS-demo.mp4`](docs/AEGIS-demo.mp4): one continuous screen recording of the running system on the demo configs below, with live AI calls; waits are fast-forwarded and labeled on screen. Synthetic narration voice and an animated presenter; subtitles in [`AEGIS-demo.srt`](docs/AEGIS-demo.srt), a silent copy ([`AEGIS-demo-no-voice.mp4`](docs/AEGIS-demo-no-voice.mp4)) and the timed script ([`AEGIS-demo-narration.md`](docs/AEGIS-demo-narration.md)) for a voice-over |
| Technical presentation (5 slides) | [`docs/AEGIS-Technical-Presentation.pdf`](docs/AEGIS-Technical-Presentation.pdf) / [`.pptx`](docs/AEGIS-Technical-Presentation.pptx) |
| Full engineering reference | [`docs/architecture-document.md`](docs/architecture-document.md), with a build-status table in §0 |
| Demo configs + walkthrough | [`samples/sample_input_config_files/README.md`](samples/sample_input_config_files/README.md) |

## How a config flows through AEGIS

1. **Redaction**: secrets (enable/user hashes, type-7 and plain passwords, SNMP communities and SNMPv3 keys, IPsec PSKs, RADIUS/TACACS+ keys, routing keys, FortiOS `ENC` values, Junos quoted secrets, XML/JSON secret fields) are replaced with typed placeholders *before anything else runs*. Original values exist only in memory for the duration of one request, never stored, never sent to an AI, never returned by the API.
2. **Fingerprint + device identity**: format detection is generic code; *which vendor* is data (each `seeds/<vendor>.yaml` carries its own fingerprint). Hostname, model, serial and firmware are read where present (e.g. Cisco `license udi pid … sn …`, `show version`, Arista/Junos/FortiOS headers). The SHA-256 of the uploaded file is recorded and printed on the report.
3. **Units with context**: one unit per setting. Block-structured CLI (Junos `{ }`, FortiOS `config/edit/end`) is flattened with each setting's full parent path; banner text and free-text fields (descriptions, remarks) are never classified.
4. **Input-sanity gate**: any line shaped like an instruction to an AI is quarantined to human review *before any AI call*. It is one of two layers: free-text fields never reach the AI at all, so an injection the gate misses there still reaches nothing.
5. **Tiered resolution**: Tier 1: exact/regex match against the knowledge base (instant, deterministic), including known non-security structure. Tier 2: AI classification (Groq, then Gemini; or your own local model), about 12 lines per call, in parallel, cached, strictly schema- and type-validated; anything malformed, invented or mistyped falls to Tier 3. Tier 3: the human review queue; a confirmation becomes a new pattern immediately and is recorded as *human-confirmed*.
6. **Deterministic rule engine**: six predicate types, no AI in the verdict path. ACLs are evaluated in order, per list, and only the lists the device actually applies (`ip access-group`, `access-class`); a deny must cover all of the traffic in question, any overlapping permit is a violation, and an unreadable line before the decision gives *unknown*, never PASS. When one setting appears several times (two `line vty` blocks), the least secure value counts, and every source line is kept as evidence. AI-derived evidence alone never passes a CAT I control.
7. **PDF report**: a report-integrity panel (input SHA-256, rule-set fingerprint, findings digest), device identification, a plain-English summary, findings most-urgent first with the evidence line each rests on, how each was decided (instantly recognized / AI-classified / human-confirmed), why anything is unknown, and a paste-in fix (`configure terminal … write memory`) that targets the device's own failing ACL.

## Features

- **Single or bulk upload** (select several files; processed one after another)
- **Review queue** for unseen syntax, with the field picker grouped by control family, a type-aware value input, an explicit "this becomes permanent" confirmation, and optional auditor judgment (*is this security-relevant?* + notes) stored with the learned pattern
- **Blocked prompt-injection attempts** shown distinctly: red banner, sorted to the top of the queue, counted on the Overview
- **Redaction showcase**: per type, what was caught and what the redacted line looks like in place
- Multi-framework selection (any combination of CIS / NIST / STIG / ISO), per-device PDF, Overview and Insights dashboards, Langfuse tracing of every LLM call (cloud mode)
- **New vendors, two ways**: learned in the GUI (an unknown vendor's lines go to the review queue; the reviewer can also *name* the vendor by picking a line from its config header, so its patterns get their own knowledge-base bucket and its next device is recognized), or pre-loaded in bulk as one seed YAML file (fingerprint + patterns + defaults), as done for Cisco IOS/IOS-XE, pfSense, SONiC, Juniper Junos and FortiOS; regex patterns can capture values (`idle-timeout (\d+)` → the number)
- **Air-gapped mode**: `AEGIS_LLM_MODE=local` (self-hosted OpenAI-compatible model only) or `off` (no AI; every unknown line goes to a human)
- **Tamper-evident decisions**: every reviewer decision is hash-chained; `GET /audit/verify` recomputes the chain and reports any after-the-fact edit
- **Verified reviewers** (optional): with `AEGIS_REVIEWERS` set, every write needs a reviewer token and the audit trail records the token's owner
- **Rules reload without restart**: `POST /rules/reload` re-reads `rules/*.yaml` and `seeds/*.yaml`

## Tech stack

FastAPI (Python 3.11) · SQLAlchemy + SQLite · sentence-transformers (`all-MiniLM-L6-v2`, local) · Groq `qwen/qwen3.8-27b` + Gemini `gemini-2.5-flash`, or any OpenAI-compatible local model (Ollama, vLLM) · ReportLab · Langfuse · Next.js 16 / React 19 / Tailwind v4 · pytest + GitHub Actions

## Project structure

```
backend/
  app/
    main.py             FastAPI routes; the /ingest pipeline
    redaction.py        secret redaction (runs first)
    sanity_gate.py      prompt-injection pre-filter
    fingerprint.py      format detection; vendor signatures come from seeds/*.yaml
    units.py            config -> units with context (CLI lines, brace/config blocks, XML, JSON)
    resolve.py          Tier 1 / 2 / 3 resolution
    llm_client.py       cloud / local / off classifier + response validation
    rule_engine.py      deterministic evaluation, 6 predicate types, fail-closed ACL parser
    audit_chain.py      hash chain over human decisions
    pdf_report.py       ReportLab report
    rules/*.yaml        the 39 rules (each file's header states its source + verification)
    seeds/*.yaml        one file per vendor: fingerprint + Tier-1 patterns
  eval/                 golden set, verdict ground truth, injection probe (+ results/)
  tests/                245 offline tests (no API keys, LLM/embedder mocked)
  requirements.txt      pinned runtime deps; requirements-dev.txt adds pytest
frontend/               Next.js console: Overview, Analyze, Review queue, Insights
samples/                demo configs (see below)
docs/                   architecture documents + diagram
```

## Running it locally

Requirements: **Python 3.11**, **Node.js 20+** (developed on 22), and free API keys for [Groq](https://console.groq.com) and/or [Gemini](https://aistudio.google.com). Langfuse keys are optional.

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # fill in GROQ_API_KEY and/or GEMINI_API_KEY (Langfuse optional)
python -m uvicorn app.main:app --port 8000
```

The first start downloads the embedding model (~90 MB) and takes 10-30 s; wait for `Application startup complete`. The database (`backend/sentra.db`) is created and seeded automatically. To start from a clean slate, stop the server and delete that file. With no AI keys at all AEGIS still runs: every line the knowledge base doesn't know simply goes to the review queue.

On a machine without a GPU, `pip install torch --index-url https://download.pytorch.org/whl/cpu` before the requirements keeps the install small (this is what CI does).

### Configuration (environment variables, all optional)

| Variable | Effect |
|---|---|
| `AEGIS_LLM_MODE` | `cloud` (default: Groq, then Gemini), `local` (only `AEGIS_LOCAL_LLM_URL`, e.g. `http://localhost:11434/v1` for Ollama, model `AEGIS_LOCAL_LLM_MODEL`; Langfuse export off), or `off` (no AI) |
| `AEGIS_REVIEWERS` | `name:token,name2:token2` turns on verified reviewer identity; the frontend sends its token from `NEXT_PUBLIC_AEGIS_TOKEN` or `localStorage["aegis:token"]` |
| `AEGIS_CORS_ORIGINS` | allowed browser origins (default `http://localhost:3000,http://127.0.0.1:3000`) |
| `AEGIS_MAX_UPLOAD_BYTES` | upload size limit (default 5 MB) |

For a fully air-gapped install, also pre-download the embedding model once and set `HF_HUB_OFFLINE=1`.

### Frontend

```bash
cd frontend
npm install
cp .env.local.example .env.local
npm run dev
```

Open http://localhost:3000.

### Running the tests

```bash
cd backend
pip install -r requirements-dev.txt
python -m pytest -q tests
```

The suite is fully offline (it never reads your `.env` keys or calls an LLM) and runs in CI on every push.

## Trying it out

**Quick check:** upload `samples/cisco_ios_sample.txt`, `samples/pfsense_config_sample.xml` or `samples/sonic_config_db_sample.json` on **Analyze device**.

**Guided demo (recommended):** [`samples/sample_input_config_files/`](samples/sample_input_config_files/) holds six configs derived from real public configs (Cisco IOS, Cisco IOS-XE, pfSense, SONiC, and Arista EOS as an unsupported vendor), each with its source, license and every modification documented, plus two synthetic configs in documented Junos and FortiOS syntax (`07`, `08`). In that order they show:

1. **01**: six kinds of secret redacted; instant Tier-1 matches; zero false alarms from the sanity gate.
2. **Review queue**: confirm `orgpolicy-tag SEC-BASELINE-77 apply` as *Logging enabled = Yes*.
3. **02** (pfSense XML): a blocked prompt-injection attempt in a firewall-rule description.
4. **04** (misconfigured router): the line taught in step 2 is now recognized instantly; a shadowed ACL (`permit ip any any` before `deny ... eq 23`) fails deterministically; a second injection attempt is blocked.
5. **03 / 05**: SONiC JSON, and a vendor AEGIS has never seen, degrading gracefully.
6. **07 / 08**: Juniper and FortiGate, added as YAML only: telnet enabled FAILs deterministically.
7. Download the PDF for any device.

Measured with free-tier Groq/Gemini: **8-17 s per fresh file** (it was 2-12 minutes before batching), and **about 3 s for a device whose lines AEGIS has already seen**.

## Measured results

**Verdict accuracy** (`backend/eval/verdict_labels.yaml`, `python -m eval.verdict_eval [--live]`): 73 verdicts hand-labelled from the configuration text itself (and the vendor's documented default where the config is silent), over 7 configs (Cisco IOS ×3, pfSense, SONiC, Junos, FortiOS). With the AI off: **73 of 73 correct, 0 false PASS, 0 false FAIL, none left undecided**. With the live AI: identical. CI fails the build on any wrong verdict (`tests/test_verdicts.py`). A running flow also found one false PASS the unit tests had missed (a cipher check comparing `SHA1` to `sha1` case-sensitively); it is fixed and now labelled.

**Prompt injection** (`backend/eval/injection_corpus.yaml`, `python -m eval.injection_probe`): the gate catches 32/32 variants in its tuning set and **12/20 in a held-out set written afterwards and never tuned against**, with **0 false positives** on 416 real config lines. End to end, **0 of 52** attack lines reach the AI, because free-text fields are never sent to it. The held-out number is the honest one for the gate on its own; the structural rule is what makes it safe.

**AI classifier** (golden set of 33 config lines (24 security settings + 9 negatives, Cisco IOS / pfSense / SONiC; `backend/eval/`), the production (batched) Tier-2 classifier reached **95.8% precision on the mappings it auto-accepted** and 95.8% recall, and declined all 9 non-settings. Its one wrong auto-accept (`snmp-server community public RO` read with the value "public RO", which would have hidden a default community) is now handled by a deterministic Tier-1 pattern, which is the point of the design: known shapes never depend on the AI, and every finding shows how it was decided. A small, honestly scoped set, not a broad benchmark. Re-run it with `cd backend && python -m eval.run_eval` (real API calls; results land in `backend/eval/results/`).

## Known limitations

Stated up front; see `docs/architecture-document.md` §10 for the full list:

- **Cloud AI by default.** In `cloud` mode, secrets are redacted first but config structure (hostnames, interfaces, ACL layout) goes to Groq/Gemini. `local` and `off` modes keep everything on your network; local mode is covered by tests against a stand-in endpoint, not yet benchmarked against a real local model.
- **Redaction is regex-based.** It covers the common credential shapes of the supported vendors (see `tests/test_hardening.py`), not every format: a keyword-less vendor blob, a password containing spaces, and an all-numeric key in an indented `key` line are disclosed gaps.
- **Rule coverage is a representative slice**: 39 rules, not full benchmarks; 6 check settings no sample config sets yet (ciphers, log access, segmentation). CAT levels on CIS/NIST/ISO rules are AEGIS-assigned on the STIG scale, and ISO/NIST results are device-level evidence supporting a control, not a certification of it.
- **Some per-interface semantics are coarse.** Proxy ARP is evaluated per interface; CDP is still one device-wide value, because a config doesn't say which interfaces are external. Vendor defaults are modelled for Cisco IOS (a default can fail a rule, never pass one); other vendors report a silent setting as unknown. Cross-reference linking by name (e.g. AAA method lists) is not built; Cisco ACL bindings, named ACLs, SONiC ACL rows, pfSense filter rules and FortiGate firewall policies are.
- **Learning is pattern-based**: a reviewer's decision is an exact line (or a validated regex through the API), not a model that generalizes.
- **Single-tenant build.** Reviewer tokens give verified identity, but there is no login UI or role model; the database is SQLite (Postgres + pgvector is the production path).
- **Ingestion is synchronous** (one request per file, batched AI calls inside it) with no job queue yet; free-tier API limits (for example Groq's 200,000 tokens per day) cap how many fresh devices can be classified per day.

## License

Built for Smart India Hackathon 2026. Not currently licensed for reuse outside the competition context. Sample configs in `samples/sample_input_config_files/` retain their original MIT / Apache-2.0 licenses (see that folder's README).
