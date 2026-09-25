# AEGIS — Architecture (full engineering reference)

**This is the full reference.** It is written as a design document: it
describes both what is built and what is intentionally designed-but-deferred,
often in the same section. **§0 below is the authoritative list of which is
which** — read it before citing anything later in this document as a current
capability. Companion files in this folder:
- `architecture-document-2page.md` — the condensed submission document,
  describing only what is built.
- `architecture-v2.mmd` / `architecture-v2.png` — the as-built pipeline
  diagram.
- `problem-statement.md` — the NTRO problem statement this answers.

**AEGIS** (Automated Evaluation & Governance for Infrastructure Security;
working name "Sentra" during early design, which is why the database file is
still `sentra.db`) is an AI-augmented, vendor-agnostic network device
compliance engine.

---

## 0. Build status (as of 2026-09-25)

| Capability | Status |
|---|---|
| Redaction before any AI call (11 secret types: enable/user hashes, type-7 and plain passwords, SNMP communities, SNMPv3 keys, PSKs, RADIUS/TACACS+ keys, routing keys, XML/JSON secret fields) | **Built**, regex-based. Originals are never stored anywhere. |
| Entropy-based redaction fallback | Designed, **not built** (disclosed residual risk, §10) |
| Input-sanity gate (prompt-injection pre-filter, before any LLM call; flagged items shown distinctly in the review queue) | **Built** |
| Reject non-config files outright at upload | Not built; unrecognized input is processed as an unknown vendor instead |
| Fingerprint (signature-based) + device identity extraction | **Built**; embedding-based fingerprint fallback not built |
| Tier 1 exact/regex KB match → Tier 2 LLM (schema + value-type validated) → Tier 3 review queue with KB write-back | **Built** |
| Review queue: control-family-grouped picker, confirmation step, auditor judgment (security-relevant + notes) | **Built** |
| Cross-reference / linking stage (§3.5) | Designed, **not built** |
| Canonical model on NIST 800-53 families with per-field provenance | **Built** |
| Rule engine: 6 predicate types incl. ordered first-match; vendor-scoped benchmarks; 39 cited rules across CIS / NIST / STIG / ISO | **Built** |
| Remediation from vetted per-vendor templates | **Built** (Cisco IOS, pfSense; SONiC has none yet). LLM-drafted remediation deliberately **not built** |
| Per-device PDF (executive summary, legend, severity-sorted findings, source of each decision) | **Built** |
| Single and bulk upload | **Built** (bulk = sequential, client-driven) |
| Langfuse tracing of LLM calls + human decision scored on the trace | **Built** |
| Automated tests + CI | **Built** — 146 offline tests, GitHub Actions |
| SQLite | Current DB. Postgres + pgvector is the production path, **not started** |
| Prometheus/Grafana | **Not built** — a plain `/stats` endpoint + Insights page instead |
| RBAC, multi-tenant enforcement | **Not built** — `tenant_id` / `reviewer_id` recorded, not enforced |
| Tier-1 spot-recheck sampling, framework-version drift re-evaluation | Designed, **not built** |
| Tamper-evident hash-chained audit log | **Dropped from the roadmap** (see §4) |
| Job queue, LLM rate limiting, live device polling (Netmiko) | **Not built** |
| Golden-set precision/recall measurement (§9) | **Built and run** — 33 items, 92% precision on auto-accepted, 2 wrong auto-accepts (see §9) |

---

## 1. The one design principle everything else follows

**There is exactly one parser, and it is a lookup against one knowledge base
(KB).** A "known vendor" is not a different code path from an "unknown
vendor" — it's a cache hit against the same KB that unknown-vendor handling
writes into. This is what makes "no backend redeployment to learn a new
vendor" literally true rather than a marketing claim: adding a vendor is new
rows in a database, never new code. Every other design decision below exists
in service of keeping this true.

---

## 2. Tech stack

| Layer | Choice | Why |
|---|---|---|
| Backend | FastAPI (async) | I/O-bound LLM/embedding calls benefit from async; typed models reduce integration bugs under time pressure |
| Frontend | Next.js + Tailwind | |
| DB | **SQLite for the Sept 16 demo build**; PostgreSQL is the stated production choice | zero-setup now, relational integrity either way — a finding references a rule, a device, a KB entry; not worth the setup time this week |
| Vector store | **Brute-force cosine similarity in Python for this build** (KB is a few hundred rows — trivial at this scale), used only as supporting context for Tier 2/3, scoped to the device's vendor; pgvector inside the same Postgres is the production choice | a separate vector DB is infra time with no payoff at this size; the interface is the same either way, so this is a config change later, not a rearchitecture |
| Embeddings | `sentence-transformers` `all-MiniLM-L6-v2` (local, free) | **Spike-tested Sept 13** (`spike/embedding_spike.py`): reliable for near-identical/lexical-variant matching, NOT reliable for cross-paradigm (CLI-prose vs. JSON-key-path) semantic equivalence — separation was negative on that specific case. Demoted from Tier-1 gate to a supporting signal (§3, step 4); Tier 1 is exact/structural matching instead. |
| LLM | Groq `qwen/qwen3.8-27b` primary, Gemini `gemini-2.5-flash` fallback | free-tier, abstracted behind one interface so a real deployment swaps in self-hosted Ollama without touching calling code (see §4, redaction). **Verified live Sept 13** with real API keys — the original picks (`llama-3.3-70b-versatile`, `gemini-2.0-flash`) were both decommissioned earlier in 2026 and would have failed outright; `openai/gpt-oss-120b` was also tested but is a reasoning model needing a much larger token budget, so `qwen3.8-27b` was chosen for speed and free-tier quota efficiency instead. Re-verify before the grand finale — `gemini-2.5-flash` itself is slated to retire ~Oct 16 2026. |
| PDF | ReportLab (programmatic, pure Python) | **Changed Sept 14** — WeasyPrint requires GTK3/Pango system libraries that failed to load on the dev machine (`libgobject-2.0-0` not found) and aren't guaranteed present on the actual demo machine either; not a risk worth carrying this close to the deadline. ReportLab has zero external system dependencies and is the brief's own named alternative ("ReportLab or FPDF"). |
| Parsing helper | None. `ciscoconfparse2` was considered and not adopted | units are plain CLI lines / flattened XML and JSON paths (`units.py`), so there is genuinely one resolution path for every vendor. Hierarchy-aware parsing belongs in the cross-reference stage (§3.5) when it's built. |
| Testing | pytest (146 offline tests) + GitHub Actions CI | keys blanked, LLM and embedder mocked, in-memory DB — CI needs no secrets and can't spend API quota |
| LLM observability | Langfuse (cloud free tier — a few lines of decorator code, not infra to stand up) | traces every Tier-2/3 LLM call (prompt → completion → latency/cost), and — the actual reason it's here — lets the human confirm/reject decision in the review queue attach as a score on that exact trace, which is most of our audit trail for free instead of hand-built. Cheap enough to keep even for the Sept 16 demo. |
| Pipeline observability | **A plain Next.js stats page, direct SQL queries, for the Sept 16 demo**; Prometheus + Grafana is the stated production choice | same numbers either way (tier distribution, parse coverage, queue depth — see §5) — Prometheus/Grafana is real infra setup with no demo-visible difference in the numbers shown, so it's deferred, not the stats themselves |

**Netmiko/NAPALM** (named in the brief's suggested workflow) are for *live SSH
into a device*, not parsing an uploaded file — core ingestion is file-upload,
so these are out of the critical path. Proposed as an explicit stretch
feature: live device pull against a lab/simulated device (GNS3/EVE-NG/Packet
Tracer), directly matching the brief's suggested workflow as a bonus if time
allows.

---

## 3. End-to-end pipeline

```
Upload (single/bulk: raw CLI text OR structured JSON/YAML — AWS Security
        Groups, Azure NSGs, SONiC config_db.json)
        │
        ▼
1. INPUT-SANITY GATE
   AS BUILT (2026-09-17): runs per unit, after redaction and splitting and
   before resolve_unit. Any unit shaped like an instruction to an AI
   classifier ("ignore previous instructions", "respond only with", the
   classifier's own `"canonical_field":` output format, ...) is quarantined
   straight to the review queue and flagged `sanity_gate`, so the LLM never
   sees it. Built after a real attack was demonstrated: a pfSense rule
   description fabricated an `AC.telnet_enabled: true` finding via Tier 2.
   Deliberately a deterministic pattern check, not another LLM call (which
   would share the injection surface). NOT built: rejecting whole non-config
   files up front. Review-queue text is rendered by React as plain text, never
   as HTML, so a crafted banner can't inject markup into the reviewer's page.
        │
        ▼
2. REDACTION PASS
   - Regex-scrub known secret shapes: Cisco type-7/type-5 passwords (type-7
     is reversible XOR, not a hash), SNMP community strings, IPsec/VPN
     pre-shared keys, RADIUS/TACACS+ shared secrets, embedded certs/keys.
   - AS BUILT: 11 regex rule types covering the common credential shapes of
     the supported vendors (see `redaction.py` and `tests/test_redaction.py`).
     The type digit is kept visible (`key 7 [REDACTED:AAA_KEY]`) because
     compliance rules need it; only the secret is replaced.
   - DESIGNED, NOT BUILT: an entropy-based fallback for high-entropy strings
     that match no known shape (vendor-specific hashes, base64 blobs, cloud
     IAM keys). Until it exists, redaction is best-effort over known shapes,
     never presented as a guarantee (§10).
   - The raw original is NEVER stored: it exists only in memory for the
     duration of one `/ingest` request. Everything downstream (KB lookups,
     LLM calls, the review queue, the database) sees only the redacted view.
   - Groq/Gemini free tier is a hackathon stand-in; a real deployment (e.g.
     for NTRO) runs a self-hosted model (Ollama/vLLM) inside the customer's
     perimeter. Worth being explicit that even with redaction, Tier-2/3 still
     sends real ACL structure, hostnames, and interface layout to a
     third-party API during the hackathon build — that's the specific
     exposure window the self-hosted option closes, not a hypothetical.
        │
        ▼
3a. FILE-LEVEL FINGERPRINT              3b. DEVICE IDENTITY EXTRACTION
    signature match (banner/syntax          (parallel, always runs — serial/
    markers) → vendor+version+confidence;   model/firmware populate the
    embedding fallback if below threshold.  report even if nothing else
    Degrades gracefully on partial configs  resolves, so no report is ever
    (no banner/version line) by routing     empty)
    everything through Tier 2/3 instead
    of failing.
        │
        ▼
3c. STRUCTURED-CONFIG NORMALIZER (JSON/YAML sources only: AWS Security
    Groups, Azure NSGs, GCP firewall rules, SONiC config_db.json)
    - Flattens structured objects into path-like pseudo-units
      (`IpPermissions[0].FromPort=22`) so the same resolution pipeline below
      applies uniformly — a pre-processor, not a second parser.
    - Cross-references are preserved, not dropped: a security-group rule
      referencing another security group by ID, or an Azure NSG rule using a
      service tag, is kept as an explicit reference edge (see §3.5) rather
      than flattened into an opaque string — otherwise "is this exposed to
      the internet" becomes unanswerable without resolving the reference.
        │
        ▼
3.5. CROSS-REFERENCE / LINKING STAGE (runs before per-unit resolution)
    Some controls are joined by NAME, not by proximity, and per-unit
    resolution alone cannot see this: Cisco AAA (`aaa authentication login
    ADMIN-LIST ...` and `line vty 0 4 / login authentication ADMIN-LIST` can
    be 80 lines apart, joined only by the method-list name), Juniper
    set-style policy blocks (`set security policies ... policy allow-web
    match ...` / `... policy allow-web then permit`), and cloud
    security-group-to-security-group references (§3c). This stage builds an
    explicit reference graph (name/ID → all units that cite it) BEFORE
    canonicalization, so Tier 1-3 resolution below operates on reassembled
    controls, not isolated fragments that happen to look complete in
    isolation.

    **Concretely observed, Sept 14, not theoretical**: a synthetic pfSense
    filter rule (`type=block`, `protocol=tcp`, `destination.port=23` - i.e. a
    rule that BLOCKS Telnet) was flattened into separate sibling units. Tier
    2 saw `destination.port=23` in isolation, without its sibling
    `type=block`, and classified it as `AC.telnet_enabled=true` — the
    opposite of what the rule actually does. This is not the softer
    "incomplete data" failure mode (which degrades to NOT_EVALUATED and is
    already fail-closed) — it's a genuine wrong classification, because the
    unit Tier 2 saw was individually plausible, just missing context that
    would have changed the answer. The mitigation already in place (human
    review can still catch this if it's ever surfaced at Tier 3) only helps
    when confidence is low enough to route there; this one wasn't. Building
    this stage properly is the actual fix — noted here as a specific,
    demonstrated example rather than a hypothetical, so it doesn't surprise
    anyone in a live demo or Q&A.

    **Partially addressed 2026-09-25** (after the same misclassification
    reappeared on a real-config pfSense sample): like SONiC's ACL_RULE table,
    each pfSense filter rule is now reassembled into ONE ACL-syntax line
    before resolution (`access-list pfsense-wan deny tcp any wanip eq 23`),
    in rule order, and resolved deterministically by a Tier-1 regex pattern,
    so the rule is evaluated by the same first-match engine as Cisco ACLs.
    That is a per-vendor, per-structure reassembly, not the general
    by-name reference graph this stage describes — which is still not built
    (Cisco AAA method lists remain the open example).
        │
        ▼
4. resolve_unit(unit, vendor_context) → canonical_field | None
   ONE function, ONE knowledge base, whether `unit` is a text line, a
   flattened JSON path, or a linked group from §3.5.

   **Revised Sept 13, after the Day-1 embedding spike test (results in
   `spike/embedding_spike.py`).** The original design gated Tier 1 on cosine
   similarity ≥ 0.85 and routed the 0.4-0.85 band to Tier 2. The spike
   disproved that: for cross-paradigm pairs specifically (CLI prose vs.
   flattened JSON key-paths — exactly the SONiC case), a genuinely-equivalent
   pair scored *lower* (0.155) than a genuinely-different pair (0.212).
   General sentence embeddings don't reliably separate CLI/JSON syntax by
   security meaning once the surface form differs enough — a real finding,
   not a tuning nit. Corrected design, simpler than the one it replaces:

   Tier 1  EXACT/STRUCTURAL pattern match against the KB (regex on a CLI
           line, exact key-path match on a JSON unit) → auto-mapped.
           Deterministic, not fuzzy — this IS what "known vendor" means, not
           a separate hardcoded parser. Embedding similarity is no longer the
           gate here; near-identical strings (whitespace/formatting variants)
           scored 1.000 in the spike, which is exactly what exact/structural
           matching already catches directly.
   Tier 2  Anything Tier 1 doesn't exact-match → LLM proposes
           { canonical_field, value, confidence, reasoning } as structured
           JSON, over the REDACTED unit + surrounding context. Embedding
           similarity against existing KB entries is still computed and
           passed into the prompt as supporting context ("here are the N most
           similar known patterns") — useful signal for the LLM and for a
           human reviewer, just no longer the thing that gates auto-apply.
           One-click confirm/reject UI. The model name + prompt version used
           is stored alongside the candidate (see §6, KB provenance) —
           Groq/Gemini model versions change outside our control, so
           reproducibility requires knowing which version produced a given
           historical mapping.
           HARDENING: the LLM's response is never trusted as-is. It's
           validated against a strict schema (JSON well-formed, confidence
           in range, `canonical_field` in the actual NIST-backbone enum —
           not a plausible-looking string the model invented). Any
           validation failure — malformed JSON, hallucinated field name,
           a timeout, or both Groq and Gemini unavailable — is NOT a crash
           and is NOT silently dropped: the unit is automatically routed to
           Tier 3 (human review) instead. The pipeline degrades to "needs a
           human" on any AI failure, never to "guessed and moved on" or
           "stuck." Uploads themselves always succeed and queue for
           classification even if both LLM providers are down at that
           moment — only the classification step is delayed, never lost.
   Tier 3  The LLM's own reported confidence is low, or a human rejects the
           Tier-2 proposal → Review Queue: raw (redacted, sanitized) unit
           shown to a reviewer-role human, with the same embedding-similarity
           candidate list as context. Confirmed mapping is written back into
           the KB as a NEW VERSIONED ENTRY (append-only, never mutated in
           place — see §4) — as an exact/structural pattern, so it becomes a
           real Tier-1 hit for the next config that contains it. This is the
           literal mechanism satisfying "updates its internal heuristics
           without backend redeployment": RAG-style KB growth (new rows),
           never fine-tuning.
        │
        ▼
5. NORMALIZE → Canonical Security Baseline Model (vendor-neutral JSON)
   - Top-level categories organized around NIST SP 800-53 control families
     (AC, AU, IA, SC, CM, SI, etc.) rather than an ad hoc flat field list.
     CIS, STIG, and ISO 27001 controls each map ONTO this same backbone —
     they address overlapping hardening objectives even though their
     catalogs and severity taxonomies differ, which is what makes
     "multi-framework" a real shared-schema capability instead of four
     independent, unmapped rule silos.
   - Fields are SCALAR (ssh_version, telnet_enabled) or LIST-VALUED
     (acl_rules[], enabled_ciphers[], logging_hosts[]) — required for the
     ordered-match predicate (step 6 of the rule engine, described just below).
   - `parse_coverage_pct` is reported STRATIFIED BY SEVERITY, not as one
     aggregate number — 95% overall coverage that happens to miss the 3
     CAT-I checks is a very different report than missing 3 low-severity
     ones, and an auditor needs the breakdown to notice concentrated
     high-severity gaps without hunting row-by-row.
   - Every resolved field carries full PROVENANCE: KB entry id + version,
     confidence tier, source unit id(s), and (for Tier 2) the LLM
     model/prompt version — see §6 data model.
        │
        ▼
6. RULE ENGINE (100% deterministic — no LLM in producing a verdict, by
   design, because compliance verdicts must be auditable and reproducible)
   - Rules stored as versioned YAML/JSON per (framework, framework_version):
     `cis_ios_v1.2.yaml`, `stig_paloalto_v3r1.yaml`. A framework revision is
     a new rule file, not a code change.
   - SIX generic predicate evaluator types (not per-rule code):
     1. boolean            (telnet_enabled == false)
     2. range               (session_timeout <= 600)
     3. compound             (A AND B AND NOT C)
     4. relational           (field X depends on field Y's value)
     5. set-membership       (ALL of enabled_ciphers ∈ approved_allowlist —
                              correct for checks where order doesn't matter)
     6. ORDERED / FIRST-MATCH  (does the first matching rule in acl_rules[],
                              evaluated IN SEQUENCE, deny a given
                              proto/port/source combination?) — required
                              because real ACLs, security-group rules, and
                              firewall policies are first-match evaluated.
                              A membership test alone ("does a deny-23 rule
                              exist somewhere") would score a config as safe
                              even when an earlier broad `permit any any`
                              makes that deny rule dead code. This predicate
                              simulates evaluation order, not just presence.
   - Finding.result ∈ { PASS, FAIL, NOT_EVALUATED }. Fail-closed by
     construction: a rule whose required field never resolved returns
     NOT_EVALUATED, never a silent PASS.
   - Each Finding also carries an EVALUATION SNAPSHOT, pinned at the moment
     of evaluation, not resolved live against current state: which rule
     *version* was used, which KB entry *version* produced each referenced
     field, and a timestamp. Without this, if a rule file or KB entry is
     later superseded, a historical finding's "why did we say PASS" cannot
     be reconstructed with certainty — this is the basic chain-of-custody
     bar an auditor holds any compliance tool to.
   - FRAMEWORK-VERSION DRIFT POLICY: when a framework revises (CIS bumps a
     version, DISA ships a new STIG quarter), existing findings computed
     against the old version are NOT silently left looking current. They're
     flagged stale against the new version and queued for re-evaluation —
     a report should never rest on a superseded standard without saying so.
        │
        ▼
7. REMEDIATION ENGINE
   - KB template lookup (vendor, rule_id). AS BUILT this is the ONLY source;
     with no template on file the report says so instead of improvising.
     DESIGNED, NOT BUILT: an LLM-drafted candidate, conditioned on the
     vendor's known syntax family, gated as below.
   - EVERY LLM-drafted remediation is gated behind human confirmation before
     it appears in a report or is persisted as a reusable template — the
     highest-consequence trust boundary in the system, since a wrong CLI
     command applied to a live device can take a network path down. Standing
     disclaimer on every remediation step: verify in a non-production
     environment before applying.
   - Threat model note: config content (including comments/banners) is
     attacker-influenceable input to both Tier-2 classification and
     remediation drafting — a prompt-injection surface. Mitigations: strict
     system/user prompt separation, and remediation text validated against
     an allow-listed command-family grammar for that vendor before display,
     never trusted as free text. A syntactically valid, vendor-correct
     command can still be operationally destructive (wrong interface, wrong
     ACL removed) — the grammar check validates syntax, not intent; human
     review remains the actual safety gate, which is why batch-scale
     remediation review should never be rubber-stamped in bulk.
        │
        ▼
8. PDF REPORT (per-device) + BATCH ROLLUP
   - Device identification populated independently of parse success
     elsewhere (§3b) — a wholly novel vendor's report is never empty.
   - Every finding shows: severity, remediation, evidence (exact source
     unit(s) + KB provenance), AND its confidence tier / review status
     (Tier-1 auto-matched vs. Tier-2 LLM-proposed-and-accepted vs.
     human-confirmed) — an external auditor needs to tell these apart to
     weight a PASS's evidentiary value; a report that only shows PASS/FAIL
     without this distinction hides exactly what a real auditor would ask
     for first.
   - parse_coverage_pct (stratified by severity, §6) is visible on every
     report, not buried in logs.
   - Batch rollup aggregates per-device findings — processing 50 files is a
     queue-depth difference from processing 1, not an architectural one.
```

---

## 4. Governance / audit layer (cross-cutting, not a separate module)

- **Tenant isolation.** `KnowledgeBaseEntry`, `Device`, and `CanonicalConfig`
  all carry a `tenant_id`. Even for a single-deployment hackathon build, this
  field ships now rather than later: without it, a confirmed mapping from one
  context (or a bad one from a time-pressured reviewer) silently becomes
  auto-apply logic for every future config in a *different* context. Free to
  add to the schema now; expensive to retrofit once the KB has real rows.
- RBAC: Viewer / Analyst (confirms Tier-3 mappings) / Admin (approves
  LLM-drafted remediation templates, can override rules). For the hackathon
  demo, `confirmed_by`/`reviewer_id` are stored but not yet enforced — stated
  openly, not silently assumed.
- KB entries are **append-only and versioned**, never mutated in place — a
  bad or malicious confirmation can be diffed against history and rolled
  back.
- **Reviewer judgment is recorded, not just the mapping (built 2026-09-25).**
  A Tier-3 confirmation stores whether the reviewer judged the line
  security-relevant, plus free-text auditor notes, on both the review record
  and the resulting KB entry — so "which learned patterns did a human
  explicitly judge relevant, and why" is answerable later, separately from
  *how* a mapping was decided.
- **(Designed, not built.) Spot-recheck sampling has a concrete rule, not a vague "periodically":**
  a fixed percentage (e.g. 5%) of Tier-1 auto-applied mappings per
  vendor per month are re-surfaced to a reviewer, with sample size weighted
  toward higher-severity control families first. Tier-1 bypasses human review
  by design (that's what makes it fast); this is the mechanism that bounds
  how long a bad auto-applied mapping can go undetected, since nothing else
  in the pipeline would ever re-examine it.
- **Tamper-evident audit log: dropped from the roadmap (2026-09-22).** Its
  threat model — a privileged insider editing their own organization's audit
  trail — is not what this buyer's compliance review is about (coverage and
  correctness are), and a real version (external anchoring, WORM storage) is
  multi-day work for a property nobody has asked for. If a requirement for
  tamper-evidence appears, the cheap version (a rolling hash column on
  `Finding` / `KnowledgeBaseEntry` writes) is an afternoon's work.

---

## 5. Observability layer (cross-cutting — this is how every claim below gets
checked continuously, not asserted once)

This exists because of a specific gap: every correctness claim in this
document (§9) — accuracy, fail-closed behavior, the KB "learning" a vendor —
is only real if it's measured on an ongoing basis, not just true on the day
we wrote it down. Observability is the mechanism that makes "is this still
correct" a number you can look at instead of a question you have to take on
faith.

Two tools, not one, because they answer two different questions:

**Langfuse — for anything that is an LLM call (Tier 2/3 only).**
- Every Tier-2 LLM call is traced: the redacted input unit, the prompt
  (versioned — not just the model version, the actual prompt text/version
  used), the completion, latency, token cost, per provider (Groq vs Gemini).
- The human confirm/reject decision in the review queue (§3, Tier 3) is
  attached as a **score on that exact trace** — this is most of the audit
  trail for the human-in-the-loop step, coming from the tool itself rather
  than hand-built logging.
- The golden set (§9) is run as a Langfuse **dataset**: each evaluation pass
  produces versioned precision/recall/false-negative-rate scores, tied to
  the specific prompt+model version that produced them — so "did accuracy
  change" is answerable across a prompt edit or a model swap, not just
  across time.
- Free/self-hostable, so it doesn't touch the free-tier-only constraint.

**Prometheus + Grafana — for everything that is NOT an LLM call**, i.e. the
pipeline's operational and compliance-facing state:
  - **Tier distribution over time, per vendor** (% resolved at Tier 1 vs. 2
    vs. 3) — the metric that *empirically proves* "the system learns a
    vendor, reliance on the LLM/human drops," instead of that claim resting
    only on the architecture being designed that way.
  - `parse_coverage_pct` and `NOT_EVALUATED` rate, both stratified by
    severity, trended — a rising trend on CAT-I specifically is an alerting
    condition, not a report footnote.
  - Review-queue depth and age — turns "human-in-the-loop is a genuine
    bottleneck for a new vendor" (§10) from an honest caveat into a number
    you can watch shrink.
  - Spot-recheck pass/fail rate on Tier-1 auto-confirmed entries — makes the
    governance sampling in §4 a measured control, not just a stated policy.
  - Structured stage-level logging (redaction, fingerprint, rule engine,
    remediation, report generation — tenant_id, device_id, stage, duration,
    outcome) feeds this layer.

Both free/self-hosted; a live Grafana panel plus a Langfuse trace view during
the demo is a genuine "this team runs things like engineers" signal, not
decoration. **Basic alerting** sits on the Prometheus side (CAT-I
`NOT_EVALUATED` rate exceeds X%, review-queue age exceeds Y hours, LLM
validation-failure rate spikes) — doesn't need to be sophisticated for the
hackathon build, even a console/Slack alert demonstrates the capability
exists as a first-class property, not an afterthought.

---

## 6. Data model (current)

```
KnowledgeBaseEntry
  id, version, tenant_id, vendor, version_family, syntax_pattern,
  canonical_field, embedding_vector, confidence,
  source (tier1_seed | tier2_llm | tier3_human),
  llm_model_version, llm_prompt_version (both nullable — set when
    source=tier2_llm; mirrors the Langfuse trace that produced this entry),
  langfuse_trace_id (nullable — links back to the full prompt/completion
    trace and any human score attached to it),
  confirmed_by, confirmed_at, superseded_by

CanonicalConfig  (one per uploaded device config)
  id, tenant_id, device_id, vendor, version,
  parse_coverage_pct: { overall, by_severity: {CAT_I, CAT_II, CAT_III, ...} },
  fields: { <nist-control-family>.<field>: scalar | list, ... }
  provenance: { field -> {kb_entry_id, kb_entry_version, confidence_tier,
                           source_unit_ids[]} }

Device
  id, tenant_id, serial_number, model, firmware_version, source_file

Rule
  id, standard_ref (CIS/STIG/NIST/ISO id), standard_version, control_family,
  check_type (boolean|range|compound|relational|set-membership|
              ordered-first-match),
  predicate, severity, remediation_template_ref

Finding
  id, device_id, rule_id, rule_version_at_evaluation, result
  (PASS|FAIL|NOT_EVALUATED), severity, evaluated_at,
  confidence_tier (tier1|tier2_accepted|tier3_human_confirmed),
  evidence: { source_unit_ids[], kb_entry_id, kb_entry_version },
  remediation_text, remediation_source (template | llm-drafted-confirmed),
  stale (bool — true once standard_version has been superseded)

ReviewQueueItem
  id, tenant_id, raw_unit (redacted + sanitized), context, candidate_mapping,
  confidence, status (pending | confirmed | rejected), reviewer_id
```

---

## 7. MVP scope — realistic as of Sept 12, for a working demo by Sept 16

Real build time is 3 days (13th-15th) — the 16th is presentation day, the
17th is the internal hackathon itself, not more build time. This section was
re-cut on Sept 12 to reflect that, and is now the actual target, not an
aspiration — everything in "stays real" below must run live; everything in
"deferred" is described elsewhere in this document as the target design but
is NOT part of the Sept 16 build.

**Device coverage — one from each of the three top-level categories the
brief names — unchanged:**
- **Firewalls & SASE → pfSense (Netgate).** Seeded Tier 1. Free/open-source,
  so the team stands up a real instance and exports a genuine config rather
  than fabricating one (§9's no-invented-data constraint).
- **Routers & Switches → Cisco IOS (Catalyst).** Seeded Tier 1. Real configs
  via Packet Tracer/GNS3.
- **Specialized Networking → SONiC (`config_db.json`).** The ONE run through
  Tier 2 → Tier 3 — the brief names SONiC by name as the case that breaks
  traditional parsers, so this is the narratively correct choice for the
  "learns in front of the judges" moment, and it doubles as the
  structured-JSON demo. **Its demo controls are deliberately chosen to be
  resolvable within a single config block** — nothing requiring the
  cross-reference linking stage below, which is not being built this week.
- **Policy for this moment, revised after review: record a successful run in
  advance and present the recording as the primary demo for the Sept 16/17
  internal round.** Free-tier rate limits during a live judged run are a real
  risk with no acceptable partial-credit outcome — a failed live demo is
  remembered more than the architecture behind it. A **live** attempt is a
  stretch goal only, and only after real hardening (retry/backoff, a
  pre-warmed cache of the demo path, a second Gemini key as a backup-to-the-
  backup) — that hardening work is realistically a grand-finale-stage
  investment, not something to add under this week's time pressure.

**Day 1 priority — done, Sept 13, before any other code was written**:
spike-tested the embedding model against hand-picked near-duplicate and
non-duplicate pairs (`spike/embedding_spike.py`). Result: general sentence
embeddings do NOT reliably cluster CLI-vs-JSON cross-paradigm pairs by
security meaning (negative separation on that case). This was the single
biggest unvalidated risk in the design, and it changed the actual mechanism
— Tier 1 is now exact/structural matching, not a fuzzy cosine threshold (see
§3, step 4, and §2's Embeddings row) — rather than being discovered on day 3
with code already built on the old assumption.

**Stays real and working for the Sept 16 demo:**
- FastAPI + Next.js + SQLite (§2) — not Postgres, not Chroma, this week.
- Redaction: regex-only (no entropy fallback yet). **The demo should
  deliberately include one failure case** — a secret shape neither layer
  catches slipping through — rather than only showing the happy path. A
  judge or auditor will ask "what doesn't this catch" regardless; showing it
  ourselves, with the entropy-fallback answer already in hand (§10), reads as
  in-control rather than caught out.
- Fingerprinting: signature/banner match only (no embedding-based file-level
  fallback yet).
- The full tiered resolve pipeline for real: Tier 1 exact/regex KB match
  (brute-force cosine similarity only as supporting context), Tier 2 Groq/Gemini with the schema-validation +
  auto-fallback-to-Tier-3 hardening (§3, step 4) actually wired, Tier 3 a
  real working review-queue UI — this is the differentiator and the last
  thing to cut if the schedule slips, not the first.
- All 6 rule-engine predicate types (§3, step 6) — not much harder than 4
  once the schema exists, and the ordered/first-match one is the headline
  technical claim, so it gets real testing.
- Remediation: **KB-template lookup only.** LLM-drafted remediation (§3,
  step 7) is cut entirely for the demo — worth saying on stage explicitly:
  it's the highest-risk component in the system, and rushing it under time
  pressure is a worse look than not shipping it yet.
- PDF report with evidence citations, confidence-tier visibility, and
  severity-stratified parse coverage.
- Langfuse tracing the Tier 2/3 LLM calls (§2/§5) — cheap enough to keep.
- The plain stats page (§2/§5) instead of Prometheus/Grafana.
- A small but real golden set (~20-30 hand-labeled examples, not 50-100) —
  enough for an honest precision/recall/false-negative number on the PPT,
  small enough to actually finish.
- **Updated 2026-09-15**: all four brief-named frameworks now wired and
  selectable live, not just two - CIS (Cisco IOS XE + pfSense, 21 controls),
  NIST (9), STIG (5, Cisco IOS XE Router), ISO 27001 (4) - 39 rules total.
  Originally scoped as "CIS fully, plus a thin slice of a second framework" -
  the cybersecurity teammate delivered well past that scope on her own
  initiative.
- **Updated 2026-09-16**: pfSense and ISO/IEC 27001:2022 citations checked
  directly against their real source documents too (team has local copies of
  both), same verification level as CIS and STIG now - see each rule file's
  own header comment.

**Deferred — designed and documented elsewhere in this file, not built this
week:**
- The cross-reference/linking stage (§3, step 3.5) — genuinely 1-2 days of
  work on its own; avoided by choosing demo controls (§ above) that don't
  need it, not by cutting corners on the ones that do.
- Full structured-JSON reference preservation for SONiC — simple flattening
  only for the demo, not the graph-preserving version.
- Postgres, Chroma, Prometheus/Grafana — SQLite/brute-force-cosine/stats-page
  substitutes above; these remain the *stated production choice*, not an
  abandoned idea.
- Entropy-based redaction fallback, full RBAC enforcement, multi-tenant
  isolation beyond the schema field, hash-chained audit log,
  framework-version drift re-evaluation, canonical-schema self-extension,
  live device polling via Netmiko — all already honestly caveated elsewhere
  in this document as designed-not-built; nothing new cut here, just
  restated against the harder deadline.

---

## 8. Competitive landscape

Closest existing tools: **Titania Nipper** (network config compliance
auditing against CIS/STIG — curated/vendor-locked to assessed device types),
SolarWinds NCM, Qualys Policy Compliance (fixed device/benchmark libraries),
vendor-native NMS (locked to that vendor). Differentiator to lead with:
adapts to an unseen vendor without a vendor-side product update, via the KB
growth mechanism in §3-4, not a larger hardcoded device library.

---

## 9. Evaluation & integrity methodology — "what is your ground truth?"

**Measured 2026-09-25 (ground truth #1):** On a hand-labeled, held-out golden set of 33 config lines (24 security settings + 9 negatives, Cisco IOS / pfSense / SONiC; `backend/eval/`), the live Tier-2 classifier reached **92% precision on the mappings it auto-accepted** and 95.8% recall, and declined 8 of 9 non-settings. It auto-accepted **2 wrong mappings (6.1%)** — `transport input none` read as a VTY access restriction, and a pfSense `lan.subnet=24` read as network segmentation — which is exactly why Tier-1 matches win over AI guesses and every finding shows how it was decided. A small, honestly scoped set, not a broad benchmark. Reproduce with `cd backend && python -m eval.run_eval`; each run is saved to `backend/eval/results/` with the model and prompt versions that produced it.

This is a question a judge will ask directly, so the answer needs to be more
than "we tested it." There are three distinct ground-truth sources here, for
three distinct claims — conflating them is how teams end up with an answer
that falls apart under a follow-up question.

**Ground truth #1 — for "does this line/unit mean what we said it means"
(the parsing/classification layer):** a hand-labeled golden set of real
vendor config lines and JSON paths, labeled against the *vendor's own
official documentation*, held out from anything the KB matches or the LLM
is prompted with. This gives real precision/recall on Tier 1-3 routing — not
asserted thresholds (§2).

**Ground truth #2 — for "is a PASS/FAIL verdict actually correct" (the rule
engine):** the CIS/NIST/STIG/ISO texts themselves are the ground truth for
what "compliant" means — we don't invent policy, we encode theirs. Concretely,
this is operationalized as a known-state test suite: configs where the team
deliberately sets a control to a specific compliant or non-compliant state
and independently determines the correct verdict *by hand*, following the
published standard — the same way a human auditor would. That manual
determination is the test oracle; there isn't a more authoritative one,
because "compliant" is definitionally what the standard says a qualified
reader determines it to be. Where DISA/NIST already publish machine-readable
**SCAP/OVAL reference definitions** for a control, the rule engine's verdict
is validated against those directly — a stronger, third-party-maintained
ground truth than our own interpretation alone, used wherever it exists.

**Ground truth #3 — is any of this still true over time?** Both golden sets
above are re-run on a schedule via the observability layer (§5), not measured
once before a demo and left stale. "Still correct" is a number you can look
at, not a claim frozen at submission time.

**The headline metric is false-negative rate, not overall accuracy.** A
false PASS (reporting compliant when a device isn't) is the actively
dangerous failure mode for a compliance tool — a false sense of security is
worse than no tool. We report this number specifically rather than letting a
high aggregate accuracy hide it.

Any accuracy/confidence number that appears on the PPT or in the report must
come from an actual run against one of these ground truths, or be clearly
labeled as a projection sourced from a cited external study — never
presented as a measured result that wasn't actually measured.

---

## 10. Constraints this design is honest about

- **This is RAG, not model training.** No GPU, no fine-tuning pipeline. This
  is the right scope for the timeframe and is *also* the right scope for
  "no redeployment to learn a new vendor" — those two constraints point at
  the same architecture, which is a good sign it's the right one.
- **Human-in-the-loop is a genuine bottleneck for the first few configs of a
  new vendor**, and gets lighter as the KB fills in for that vendor. Stated
  upfront as a tradeoff, not implied away.
- **Remediation auto-generation is the highest-risk component** and is
  deliberately the most gated — never auto-applied, always human-confirmed,
  always disclaimed.
- **Redaction is regex-only in this build, not a formal guarantee.** It
  covers the common credential shapes of the supported vendors (each one has
  a regression test) and will miss shapes nobody wrote a pattern for — e.g. a
  Juniper `encrypted-password "$6$..."` with no recognizable keyword, kept as
  a deliberate, tested demo of the gap. The entropy fallback is the stated
  next layer. Building the real-config demo set (2026-09-25) found and fixed
  a worse class of bug here — secrets that were *counted* as redacted while
  the value stayed in place (the type digit got replaced instead) — which is
  why every redaction test now asserts the secret is absent from the output,
  not just that a hit was reported.
- **pfSense empty flag elements outside filter rules** (e.g.
  `<syslog><enable/>`, `<wan><blockpriv/>`) are still dropped by generic XML
  flattening. Filter rules themselves are handled: since 2026-09-25 each rule
  is reassembled into one ACL-syntax line, `<any/>` and `<log/>` included
  (see §3.5).
- **Observed Sept 14, not a code bug**: Groq per-call latency for the same
  model/prompt varied from ~0.5s to ~5.5s across one afternoon of repeated
  testing (checked via Langfuse trace latencies directly, not guessed) —
  almost certainly free-tier throttling under sustained load, since units
  are still resolved correctly, just slower. A 10-12 unit config can take
  30-45s end to end under this condition, serially. This reinforces, rather
  than changes, the existing policy (§7): the live-learning demo moment is
  recorded in advance, not attempted cold, and the team should stop running
  heavy repeated test ingests in the hour or two directly before the actual
  presentation, to let free-tier rate limits recover. Parallelizing Tier-2
  calls within one ingest would help and is a reasonable grand-finale-stage
  improvement, but restructuring that now, under time pressure, risks
  introducing a concurrency bug in the DB-write path for less benefit than
  the simpler mitigation above.
- **Fixed Sept 14, real bug, not hypothetical**: `/ingest` was originally
  declared `async def` while doing fully synchronous, blocking work inside
  it (LLM calls, embedding computation). An async route runs directly on
  FastAPI's single event loop, so that blocking work stalled the entire
  server for its duration — a concurrent `GET /stats` measured during a
  14-second ingest would have queued behind it indefinitely. Every other
  route was already a plain `def` (which FastAPI dispatches to a thread
  pool automatically) — only `/ingest` had this. Changed to a plain `def`;
  verified with a concurrency test that a `/stats` call fired mid-ingest now
  returns in ~2s instead of hanging. The residual ~2s is expected SQLite
  single-writer contention, not a new problem.

---

## 11. Pitch & demo precision notes — say these out loud, don't leave them
only in this document

A few things reviewers independently flagged as correct-on-paper but risky
if left undisclosed *verbally* — the fix is in the pitch script, not the
architecture:

- **State plainly that today's build calls a third-party API (Groq/Gemini)**,
  even redacted of secrets — real ACL structure, hostnames, and interface
  layout still leave the machine. The doc's self-hosted-Ollama answer (§3,
  step 2) is correct, but say it as the *current* honest state, not something
  a judge has to extract by asking "wait, what's actually running today?"
- **Be precise about which population the golden set covers** (§9) when
  citing its precision/recall/false-negative number — which vendors, which
  control families, ~20-30 examples. Presenting a small honestly-scoped
  number as if it were a broad one is a worse look than the number itself
  ever could be.
- **Be precise about what "regex-based redaction" means on stage**: regex +
  entropy fallback is the production target; the demo runs regex-only. Say
  the distinction, don't let "redaction" stand in unqualified.
- **Say what's recorded versus live**: the demo video is a recording of the
  real system on the sample set in `samples/sample_input_config_files/`;
  anything on a slide that isn't in §0's "Built" rows is roadmap, and should
  be called that.
- **Rehearse the primary SONiC recorded-demo segment at least once before
  the 16th** — and say plainly on stage that it's a recording, not an
  implied-live attempt with a recording as quiet insurance. Those are two
  different postures with this team's audience, and the credibility argument
  in §9 only holds if the distinction is stated, not smoothed over.

---

## 12. Roadmap: rule authoring at scale (deliberately not built yet)

Raised 2026-09-15, decided same day: a real design question, not a gap to
apologize for. Worth stating precisely, because the easy version of the
answer ("use a vector DB for the benchmarks") is wrong in a way that matters.

**The question:** compliance-framework authoring today is manual - a human
reads the source PDF (CIS/NIST/STIG/ISO) and hand-writes the YAML rule
(`backend/app/rules/*.yaml`). Sept 15's rule-authoring pass demonstrated this
works, but also exactly how much manual verification it takes: confirming the
right benchmark family and version, checking every section number and
remediation string against the actual document rather than memory or a
web-search summary (which was independently proven unreliable mid-session -
see the Batch 1 rule-authoring notes). Doesn't scale past a handful of
frameworks without tooling.

**The wrong fix: point the compliance engine itself at a searchable index of
the raw benchmark documents (RAG at evaluation time).** Rejected, for reasons
that matter for a compliance product specifically, not just in general:

- A verdict decided by "search the benchmark text, have something judge
  relevance" is not guaranteed to be the same answer twice for the same
  device state. §1's whole premise - deterministic, auditable,
  reproducible verdicts - depends on the rule engine never touching an LLM
  at evaluation time (`rule_engine.py`'s own docstring states this as the
  reason no LLM is involved in producing a verdict). Retrieval-based
  verdicts would quietly give that up.
- It reintroduces the exact free-tier latency/rate-limit problem already
  documented in §10, per control, per device, on every single evaluation,
  not once at classification time.
- It doesn't actually remove the translation step. "Set version 2 for `ip
  ssh version`" (benchmark prose) becoming `{field: ssh_version, equals: 2}`
  (an executable predicate) is a judgment call regardless of how the source
  text is stored or searched. Better retrieval doesn't make that judgment
  call disappear - it just moves the mistake from "wrong document" to
  "wrong predicate," silently, at evaluation time instead of authoring time.

**The right fix, not yet built: apply this system's own core pattern one
level up.** The tiered-resolution idea already built for parsing device
configs (deterministic match → AI-assisted classification → human
confirmation, writing back into a reusable store) is exactly the right shape
for rule *authoring* too, not just device *parsing*:

1. Ingest a benchmark PDF once into a small chunked/searchable store - one
   record per numbered recommendation (section id, title, audit text,
   remediation text), not a fine-tuned model and not the live evaluation
   path.
2. An LLM drafts a candidate canonical-field mapping and predicate per
   chunk - the same shape as the existing Tier-2 "AI suggestion" already
   shown to a human in the review queue, just aimed at benchmark text
   instead of device config lines.
3. A human (the cybersecurity teammate, today) confirms or corrects it.
4. Only on confirmation does it become a row in the same `Rule` table the
   deterministic engine already reads - nothing about execution changes.

This also directly answers "what happens when CIS ships v2.3.0 next year":
diffing chunk-by-chunk against the previous ingested version tells you
exactly which controls changed, instead of re-reading the whole document.
It does not remove the human-confirmation step, on purpose - letting a
benchmark update silently change what an already-deployed system treats as
"compliant" without a human checking is a real risk for a security product,
not a formality to automate away.

**Why not built now:** decided 2026-09-15, 1pm - the PPT is due today, the
16th is rehearsal, the 17th is fix-what-breaks-in-rehearsal (§10's own
policy: no new features that close to the demo). A new ingestion pipeline
and authoring UI is genuinely useful but is not required by the brief, and
building it this close to a live demo is exactly the kind of untested new
surface §10 already argues against introducing under time pressure. This
section exists so the answer is a considered roadmap decision if asked on
stage, not something improvised in the moment.
