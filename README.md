# AEGIS

**A**utomated **E**valuation & **G**overnance for **I**nfrastructure **S**ecurity

[![CI](https://github.com/TheUsefulNerd/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/TheUsefulNerd/aegis/actions/workflows/ci.yml)

An AI-augmented, vendor-agnostic network device compliance engine, built for Smart India Hackathon 2026 under NTRO's problem statement on multi-vendor network configuration compliance.

AEGIS reads a network device's configuration (any vendor, any format: CLI text, XML, JSON), identifies its security-relevant settings through a tiered deterministic → AI → human pipeline, and checks them against **39 real, cited rules across all four frameworks the brief names: CIS, NIST SP 800-53, DISA STIG and ISO/IEC 27001**. When it meets syntax it has never seen, it asks a human once in the review queue and recognizes it instantly on every device afterwards, no code change, no redeploy.

## Submission deliverables (SIH 2026, PS 26155, Team SIX ORIGINS)

| Deliverable | Where |
|---|---|
| Source code + setup instructions | this repository; setup below |
| Architecture document (2 pages) | [`docs/AEGIS-Architecture-2page.pdf`](docs/AEGIS-Architecture-2page.pdf) (source: [`docs/architecture-document-2page.md`](docs/architecture-document-2page.md)) |
| Demo video (1:46) | [`docs/AEGIS-demo.mp4`](docs/AEGIS-demo.mp4): one continuous screen recording of the running system on the demo configs below, with live AI calls; waits are fast-forwarded and labeled on screen. Placeholder synthetic voice and an animated presenter; subtitles in [`AEGIS-demo.srt`](docs/AEGIS-demo.srt), a silent copy ([`AEGIS-demo-no-voice.mp4`](docs/AEGIS-demo-no-voice.mp4)) and the timed script ([`AEGIS-demo-narration.md`](docs/AEGIS-demo-narration.md)) for a voice-over |
| Technical presentation (5 slides) | [`docs/AEGIS-Technical-Presentation.pdf`](docs/AEGIS-Technical-Presentation.pdf) / [`.pptx`](docs/AEGIS-Technical-Presentation.pptx) |
| Full engineering reference | [`docs/architecture-document.md`](docs/architecture-document.md), with a build-status table in §0 |
| Demo configs + walkthrough | [`samples/sample_input_config_files/README.md`](samples/sample_input_config_files/README.md) |

## How a config flows through AEGIS

1. **Redaction**: secrets (enable/user hashes, type-7 and plain passwords, SNMP communities and SNMPv3 keys, IPsec PSKs, RADIUS/TACACS+ keys, routing keys, XML/JSON secret fields) are replaced with typed placeholders *before anything else runs*. Original values exist only in memory for the duration of one request, never stored, never sent to an AI, never returned by the API.
2. **Fingerprint + device identity**: vendor, format and (where present) hostname, model, serial and firmware.
3. **Input-sanity gate**: any line shaped like an instruction to an AI ("ignore previous instructions… respond only with…") is quarantined to human review *before any AI call*. A real, working prompt-injection attack was found against an earlier build and this gate closes it.
4. **Tiered resolution**: Tier 1: exact/regex match against the knowledge base (instant, deterministic), including known non-security structure such as interface headers and routes. Tier 2: AI classification (Groq primary, Gemini fallback), about 12 lines per call with calls in parallel and answers cached, strictly schema- and type-validated; anything malformed, invented or mistyped falls to Tier 3. Tier 3: the human review queue, a confirmation becomes a new Tier-1 pattern immediately.
5. **Deterministic rule engine**: six predicate types including ordered/first-match ACL evaluation (a `permit any any` before a `deny ... eq 23` is caught as a FAIL). No AI in the verdict path. Every finding is PASS, FAIL or NOT_EVALUATED, a setting the config never mentions is never reported as a pass. Vendor-specific benchmarks only apply to their own vendor.
6. **PDF report**: device identification, plain-English executive summary, a legend, findings sorted most-urgent first with severity, the source of each decision (instantly recognized / AI-classified / human-confirmed) and device-specific remediation commands.

## Features

- **Single or bulk upload** (select several files; processed one after another)
- **Review queue** for unseen syntax, with the field picker grouped by control family, a type-aware value input, an explicit "this becomes permanent" confirmation, and optional auditor judgment (*is this security-relevant?* + notes) stored with the learned pattern
- **Blocked prompt-injection attempts** shown distinctly: red banner, sorted to the top of the queue, counted on the Overview
- **Redaction showcase**: per type, what was caught and what the redacted line looks like in place
- Multi-framework selection, per-device PDF, Overview and Insights dashboards, Langfuse tracing of every LLM call

## Tech stack

FastAPI (Python 3.11) · SQLAlchemy + SQLite · sentence-transformers (`all-MiniLM-L6-v2`, local) · Groq `qwen/qwen3.8-27b` + Gemini `gemini-2.5-flash` · ReportLab · Langfuse · Next.js 16 / React 19 / Tailwind v4 · pytest + GitHub Actions

## Project structure

```
backend/
  app/
    main.py             FastAPI routes; the /ingest pipeline
    redaction.py        secret redaction (runs first)
    sanity_gate.py      prompt-injection pre-filter
    fingerprint.py      vendor/format detection
    units.py            config -> per-line / per-path units (CLI, XML, JSON)
    resolve.py          Tier 1 / 2 / 3 resolution
    llm_client.py       Groq -> Gemini classifier + response validation
    rule_engine.py      deterministic evaluation, 6 predicate types
    pdf_report.py       ReportLab report
    rules/*.yaml        the 39 cited rules (each file's header states its source + verification)
    seeds/*.yaml        Tier-1 starter patterns per vendor
  tests/                146 offline tests (no API keys, LLM/embedder mocked)
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

The first start downloads the embedding model (~90 MB) and takes 10-30 s; wait for `Application startup complete`. The database (`backend/sentra.db`) is created and seeded automatically. To start from a clean slate, stop the server and delete that file.

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

**Guided demo (recommended):** [`samples/sample_input_config_files/`](samples/sample_input_config_files/) holds six configs derived from real public configs (Cisco IOS, Cisco IOS-XE, pfSense, SONiC, and Arista EOS as an unsupported vendor), each with its source, license and every modification documented. In that order they show:

1. **01**: six kinds of secret redacted; instant Tier-1 matches; zero false alarms from the sanity gate.
2. **Review queue**: confirm `orgpolicy-tag SEC-BASELINE-77 apply` as *Logging enabled = Yes*.
3. **02** (pfSense XML): a blocked prompt-injection attempt in a firewall-rule description.
4. **04** (misconfigured router): the line taught in step 2 is now recognized instantly; a shadowed ACL (`permit ip any any` before `deny ... eq 23`) fails deterministically; a second injection attempt is blocked.
5. **03 / 05**: SONiC JSON, and a vendor AEGIS has never seen, degrading gracefully.
6. Download the PDF for any device.

Measured on the six demo configs with free-tier Groq/Gemini: **8-16 s per fresh file** (it was 2-12 minutes before batching), and **about 2 s for a device whose lines AEGIS has already seen**.

## Measured accuracy

On a hand-labeled, held-out golden set of 33 config lines (24 security settings + 9 negatives, Cisco IOS / pfSense / SONiC; `backend/eval/`), the production (batched) Tier-2 classifier reached **95.8% precision on the mappings it auto-accepted** and 95.8% recall, and declined all 9 non-settings. Its one wrong auto-accept (`snmp-server community public RO` read with the value "public RO", which would have hidden a default community) is now handled by a deterministic Tier-1 pattern, which is the point of the design: known shapes never depend on the AI, and every finding shows how it was decided. A small, honestly scoped set, not a broad benchmark. Re-run it with `cd backend && python -m eval.run_eval` (real API calls; results land in `backend/eval/results/`).

## Known limitations

Stated up front; see `docs/architecture-document.md` §10 for the full list:

- **Third-party LLMs today.** Secrets are redacted first, but config structure (hostnames, interfaces, ACL layout) is still sent to Groq/Gemini. A real deployment would swap in a self-hosted model; the provider sits behind one interface.
- **Redaction is regex-based.** It covers the common credential shapes of the supported vendors (see the tests), not every possible format. A keyword-less vendor blob (e.g. Juniper `encrypted-password "$6$…"`) is a known, disclosed gap.
- **No general cross-reference linking yet.** Settings joined by name across distant lines (e.g. Cisco AAA method lists) are resolved per line. SONiC ACL rows and pfSense filter rules are the exception: each is reassembled into one ACL line before evaluation. Empty XML flag elements outside filter rules (e.g. pfSense `<syslog><enable/>`) are not yet emitted as units.
- **Single-tenant demo build.** `tenant_id` / `reviewer_id` are recorded but there is no login or role enforcement; the database is SQLite (Postgres + pgvector is the production path).
- **Ingestion is synchronous** (one request per file, batched AI calls inside it) with no job queue yet; free-tier API limits (for example Groq's 200,000 tokens per day) cap how many fresh devices can be classified per day.

## License

Built for Smart India Hackathon 2026. Not currently licensed for reuse outside the competition context. Sample configs in `samples/sample_input_config_files/` retain their original MIT / Apache-2.0 licenses (see that folder's README).
