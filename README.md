# AEGIS

**A**utomated **E**valuation & **G**overnance for **I**nfrastructure **S**ecurity

[![CI](https://github.com/TheUsefulNerd/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/TheUsefulNerd/aegis/actions/workflows/ci.yml)

An AI-augmented, vendor-agnostic network device compliance engine, built for Smart India Hackathon 2026 under NTRO's problem statement on multi-vendor network configuration compliance.

AEGIS reads a network device's configuration — any vendor, any format (CLI text, XML, JSON) — identifies its security-relevant settings through a tiered deterministic → AI → human pipeline, and checks them against **39 real, cited rules across all four frameworks the brief names: CIS, NIST SP 800-53, DISA STIG and ISO/IEC 27001**. When it meets syntax it has never seen, it asks a human once in the review queue and recognizes it instantly on every device afterwards — no code change, no redeploy.

- Full technical design: [`docs/architecture-document.md`](docs/architecture-document.md)
- 2-page submission version: [`docs/architecture-document-2page.md`](docs/architecture-document-2page.md)
- Demo configs and walkthrough: [`samples/sample_input_config_files/README.md`](samples/sample_input_config_files/README.md)

## How a config flows through AEGIS

1. **Redaction** — secrets (enable/user hashes, type-7 and plain passwords, SNMP communities and SNMPv3 keys, IPsec PSKs, RADIUS/TACACS+ keys, routing keys, XML/JSON secret fields) are replaced with typed placeholders *before anything else runs*. Original values exist only in memory for the duration of one request — never stored, never sent to an AI, never returned by the API.
2. **Fingerprint + device identity** — vendor, format and (where present) hostname, model, serial and firmware.
3. **Input-sanity gate** — any line shaped like an instruction to an AI ("ignore previous instructions… respond only with…") is quarantined to human review *before any AI call*. A real, working prompt-injection attack was found against an earlier build and this gate closes it.
4. **Tiered resolution** — Tier 1: exact/regex match against the knowledge base (instant, deterministic). Tier 2: LLM classification (Groq primary, Gemini fallback), strictly schema- and type-validated; anything malformed, invented or mistyped falls to Tier 3. Tier 3: the human review queue — a confirmation becomes a new Tier-1 pattern immediately.
5. **Deterministic rule engine** — six predicate types including ordered/first-match ACL evaluation (a `permit any any` before a `deny ... eq 23` is caught as a FAIL). No AI in the verdict path. Every finding is PASS, FAIL or NOT_EVALUATED — a setting the config never mentions is never reported as a pass. Vendor-specific benchmarks only apply to their own vendor.
6. **PDF report** — device identification, plain-English executive summary, a legend, findings sorted most-urgent first with severity, the source of each decision (instantly recognized / AI-classified / human-confirmed) and device-specific remediation commands.

## Features

- **Single or bulk upload** (select several files; processed one after another)
- **Review queue** for unseen syntax, with the field picker grouped by control family, a type-aware value input, an explicit "this becomes permanent" confirmation, and optional auditor judgment (*is this security-relevant?* + notes) stored with the learned pattern
- **Blocked prompt-injection attempts** shown distinctly — red banner, sorted to the top of the queue, counted on the Overview
- **Redaction showcase** — per type, what was caught and what the redacted line looks like in place
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
  tests/                138 offline tests (no API keys, LLM/embedder mocked)
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

The first start downloads the embedding model (~90 MB) and takes 10–30 s; wait for `Application startup complete`. The database (`backend/sentra.db`) is created and seeded automatically. To start from a clean slate, stop the server and delete that file.

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

The suite is fully offline — it never reads your `.env` keys or calls an LLM — and runs in CI on every push.

## Trying it out

**Quick check:** upload `samples/cisco_ios_sample.txt`, `samples/pfsense_config_sample.xml` or `samples/sonic_config_db_sample.json` on **Analyze device**.

**Guided demo (recommended):** [`samples/sample_input_config_files/`](samples/sample_input_config_files/) holds six configs derived from real public configs (Cisco IOS, Cisco IOS-XE, pfSense, SONiC, and Arista EOS as an unsupported vendor), each with its source, license and every modification documented. In that order they show:

1. **01** — six kinds of secret redacted; instant Tier-1 matches; zero false alarms from the sanity gate.
2. **Review queue** — confirm `orgpolicy-tag SEC-BASELINE-77 apply` as *Logging enabled = Yes*.
3. **02** (pfSense XML) — a blocked prompt-injection attempt in a firewall-rule description.
4. **04** (misconfigured router) — the line taught in step 2 is now recognized instantly; a shadowed ACL (`permit ip any any` before `deny ... eq 23`) fails deterministically; a second injection attempt is blocked.
5. **03 / 05** — SONiC JSON, and a vendor AEGIS has never seen, degrading gracefully.
6. Download the PDF for any device.

Every line AEGIS can't recognize is one LLM call, so a fresh ~80-line config takes a few minutes on the free tier. Once patterns are learned, repeat devices are near-instant.

## Known limitations

Stated up front — see `docs/architecture-document.md` §10 for the full list:

- **Third-party LLMs today.** Secrets are redacted first, but config structure (hostnames, interfaces, ACL layout) is still sent to Groq/Gemini. A real deployment would swap in a self-hosted model; the provider sits behind one interface.
- **Redaction is regex-based.** It covers the common credential shapes of the supported vendors (see the tests), not every possible format. A keyword-less vendor blob (e.g. Juniper `encrypted-password "$6$…"`) is a known, disclosed gap.
- **No cross-reference linking yet.** Settings joined by name across distant lines (Cisco AAA method lists, pfSense filter rules split across sibling elements) are resolved per line. Empty XML flag elements (e.g. pfSense `<any/>`) are not yet emitted as units.
- **Single-tenant demo build.** `tenant_id` / `reviewer_id` are recorded but there is no login or role enforcement; the database is SQLite (Postgres + pgvector is the production path).
- **Ingestion is synchronous**, one LLM call at a time, with no job queue or rate limiting yet.

## License

Built for Smart India Hackathon 2026. Not currently licensed for reuse outside the competition context. Sample configs in `samples/sample_input_config_files/` retain their original MIT / Apache-2.0 licenses (see that folder's README).
