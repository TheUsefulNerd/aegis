"use client";

import { useEffect, useState } from "react";
import { Check, X, HelpCircle, Sparkles, CheckCheck, ShieldAlert, ArrowLeft } from "lucide-react";
import {
  ReviewQueueItem,
  FieldMeta,
  confirmReviewItem,
  getCanonicalFields,
  listReviewQueue,
  rejectReviewItem,
} from "@/lib/api";
import { CONTROL_FAMILY_LABELS } from "@/lib/copy";
import {
  Panel,
  PageHeader,
  SectionLabel,
  Button,
  Badge,
  TechnicalDetails,
  Spinner,
  EmptyState,
  InlineToast,
  useToast,
} from "@/components/ui";

const REVIEWER_ID = "lead"; // single-reviewer demo; RBAC is schema-only for now (architecture-document.md §4)

export default function ReviewQueuePage() {
  const [items, setItems] = useState<ReviewQueueItem[]>([]);
  const [fieldMeta, setFieldMeta] = useState<Record<string, FieldMeta>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [toast, setToast] = useToast();

  useEffect(() => {
    Promise.all([listReviewQueue("pending"), getCanonicalFields()])
      .then(([q, f]) => {
        setItems(q);
        setFieldMeta(f);
        setSelectedId((prev) => prev ?? q[0]?.id ?? null);
      })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false));
  }, []);

  function handleResolved(id: string, message: string) {
    setItems((prev) => {
      const next = prev.filter((i) => i.id !== id);
      setSelectedId((current) => (current === id ? next[0]?.id ?? null : current));
      return next;
    });
    setToast({ type: "success", text: message });
  }

  const selected = items.find((i) => i.id === selectedId) ?? null;
  const blockedCount = items.filter((i) => i.flag_type === "sanity_gate").length;

  return (
    <div>
      <PageHeader
        title="Review queue"
        description="Settings AEGIS couldn't classify on its own. Confirm the AI's guess, correct it, or say it isn't security-relevant — once resolved, AEGIS recognizes it instantly next time, on any device."
        actions={
          !loading && (
            <>
              {blockedCount > 0 && <Badge color="rose">{blockedCount} blocked</Badge>}
              <Badge color={items.length > 0 ? "amber" : "emerald"}>{items.length} pending</Badge>
            </>
          )
        }
      />

      <InlineToast toast={toast} />

      {error && <Panel className="p-4 border-rose-300 bg-rose-50 text-rose-800 text-sm mb-6">{error}</Panel>}

      {loading && (
        <div className="flex items-center gap-2 text-slate-500 text-sm">
          <Spinner className="size-4" /> Loading…
        </div>
      )}

      {!loading && items.length === 0 && !error && (
        <Panel>
          <EmptyState
            icon={CheckCheck}
            title="Nothing to review right now"
            description="Every setting AEGIS has seen so far was either recognized instantly or already confirmed."
          />
        </Panel>
      )}

      {!loading && items.length > 0 && (
        <div className="grid lg:grid-cols-[340px_1fr] gap-4 items-start">
          <Panel className="divide-y divide-slate-200 overflow-hidden">
            {items.map((item, i) => {
              const blocked = item.flag_type === "sanity_gate";
              const hasSuggestion = !!item.candidate_mapping && item.candidate_mapping.canonical_field !== "UNKNOWN";
              const isSelected = item.id === selectedId;
              return (
                <button
                  key={item.id}
                  onClick={() => setSelectedId(item.id)}
                  className={`w-full text-left px-4 py-3 flex gap-3 transition-colors border-l-4 ${
                    isSelected
                      ? blocked
                        ? "bg-rose-50 border-l-rose-600"
                        : "bg-slate-100 border-l-slate-900"
                      : blocked
                      ? "bg-rose-50/50 border-l-rose-300 hover:bg-rose-50"
                      : "border-l-transparent hover:bg-slate-50"
                  }`}
                >
                  <span
                    className={`shrink-0 mt-0.5 flex items-center justify-center size-5 rounded-full text-[11px] font-semibold ${
                      blocked
                        ? "bg-rose-600 text-white"
                        : isSelected
                        ? "bg-slate-900 text-white"
                        : "bg-slate-200 text-slate-600"
                    }`}
                  >
                    {i + 1}
                  </span>
                  <div className="min-w-0">
                    <div className="font-mono text-xs text-slate-700 truncate">{item.raw_unit}</div>
                    <div className="mt-1.5 flex items-center gap-1.5 text-xs">
                      {blocked ? (
                        <span className="flex items-center gap-1 font-medium text-rose-700">
                          <ShieldAlert className="size-3" /> Blocked: possible prompt injection
                        </span>
                      ) : hasSuggestion ? (
                        <span className="flex items-center gap-1 text-indigo-600">
                          <Sparkles className="size-3" /> AI suggestion
                        </span>
                      ) : (
                        <span className="text-slate-400">No suggestion</span>
                      )}
                      {item.device_hostname && (
                        <span className="text-slate-400 truncate">· {item.device_hostname}</span>
                      )}
                    </div>
                  </div>
                </button>
              );
            })}
          </Panel>

          {selected && (
            <ReviewDetail
              key={selected.id}
              item={selected}
              fieldMeta={fieldMeta}
              onResolved={handleResolved}
            />
          )}
        </div>
      )}
    </div>
  );
}

type Judgment = { isSecurityRelevant: boolean | null; notes: string };

function ReviewDetail({
  item,
  fieldMeta,
  onResolved,
}: {
  item: ReviewQueueItem;
  fieldMeta: Record<string, FieldMeta>;
  onResolved: (id: string, message: string) => void;
}) {
  const blocked = item.flag_type === "sanity_gate";
  const suggestion = item.candidate_mapping;
  const hasRealSuggestion = !blocked && !!suggestion && suggestion.canonical_field !== "UNKNOWN";
  const [mode, setMode] = useState<"default" | "manual">("default");
  const [canonicalField, setCanonicalField] = useState("");
  const [value, setValue] = useState("");
  // A mapping waiting on the reviewer's explicit second confirmation. The
  // first click only stages it - see ConfirmSummary for why.
  const [pending, setPending] = useState<{ field: string; value: unknown } | null>(null);
  const [judgment, setJudgment] = useState<Judgment>({ isSecurityRelevant: null, notes: "" });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function save(field: string, val: unknown) {
    setBusy(true);
    setErr(null);
    try {
      await confirmReviewItem(item.id, {
        canonical_field: field,
        value: val,
        reviewer_id: REVIEWER_ID,
        pattern_type: "exact",
        syntax_pattern: item.raw_unit,
        is_security_relevant: judgment.isSecurityRelevant,
        reviewer_notes: judgment.notes.trim() || null,
      });
      onResolved(item.id, `Confirmed — AEGIS will recognize "${item.raw_unit.slice(0, 40)}" instantly next time.`);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }

  async function reject(reason: string, message: string) {
    setBusy(true);
    setErr(null);
    try {
      await rejectReviewItem(item.id, {
        reviewer_id: REVIEWER_ID,
        reason,
        reviewer_notes: judgment.notes.trim() || null,
      });
      onResolved(item.id, message);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }

  return (
    <Panel className={`p-5 space-y-4 ${blocked ? "border-rose-300" : ""}`}>
      {blocked && (
        <div className="rounded-md bg-rose-50 border border-rose-300 p-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-rose-800">
            <ShieldAlert className="size-4.5 shrink-0" /> Blocked by the input-sanity gate
          </div>
          <p className="mt-1.5 text-sm text-rose-900">
            This text is shaped like an instruction to an AI classifier, not a description of a device
            setting. It was quarantined here <span className="font-semibold">before any AI call</span> — the
            AI never saw it, so it could not influence any compliance result.
          </p>
          {item.flag_reason && (
            <p className="mt-2 text-sm text-rose-900">
              <span className="font-semibold">Why:</span> {item.flag_reason}
            </p>
          )}
          {item.device_hostname && (
            <p className="mt-1 text-xs text-rose-700">
              Found in the config for {item.device_hostname}
              {item.device_vendor ? ` (${item.device_vendor})` : ""}.
            </p>
          )}
        </div>
      )}

      <div>
        <SectionLabel>Raw configuration line</SectionLabel>
        <pre
          className={`font-mono text-sm border rounded-md p-3 whitespace-pre-wrap break-words ${
            blocked ? "bg-rose-50/40 border-rose-200" : "bg-slate-50 border-slate-300"
          }`}
        >
          {item.raw_unit}
        </pre>
      </div>

      {pending ? (
        <ConfirmSummary
          rawUnit={item.raw_unit}
          field={pending.field}
          value={pending.value}
          meta={fieldMeta[pending.field]}
          busy={busy}
          onBack={() => setPending(null)}
          onConfirm={() => save(pending.field, pending.value)}
        />
      ) : (
        <>
          {blocked && mode === "default" && (
            <div className="rounded-md bg-slate-50 border border-slate-300 p-4">
              <div className="text-sm text-slate-700">
                Nothing needs to happen for the device to stay safe — this line is already excluded from its
                findings. Resolve it to clear it from the queue.
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                <Button
                  variant="danger"
                  disabled={busy}
                  onClick={() =>
                    reject("sanity_gate_confirmed", "Recorded as a blocked injection attempt — kept out of the knowledge base.")
                  }
                >
                  {busy ? <Spinner className="size-4" /> : <ShieldAlert className="size-4" />}
                  Confirm: this is an attack, keep it out
                </Button>
                <Button variant="secondary" disabled={busy} onClick={() => setMode("manual")}>
                  False alarm — it&apos;s a real setting
                </Button>
              </div>
            </div>
          )}

          {hasRealSuggestion && mode === "default" && (
            <div className="rounded-md bg-indigo-50 border border-indigo-300 p-4">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-indigo-700 uppercase tracking-wide">
                <Sparkles className="size-3.5" /> AI suggestion
              </div>
              <div className="mt-1.5 text-sm text-slate-800">
                This looks like it sets{" "}
                <span className="font-semibold">{fieldMeta[suggestion!.canonical_field]?.label ?? suggestion!.canonical_field}</span>{" "}
                to <span className="font-semibold">{String(suggestion!.value)}</span>.
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                <Button
                  variant="success"
                  disabled={busy}
                  onClick={() => setPending({ field: suggestion!.canonical_field, value: suggestion!.value })}
                >
                  <Check className="size-4" />
                  Yes, that&apos;s right
                </Button>
                <Button variant="secondary" disabled={busy} onClick={() => setMode("manual")}>
                  <HelpCircle className="size-4" />
                  Not quite — let me fix it
                </Button>
              </div>
              <TechnicalDetails label="Why the AI thinks this">
                <p className="text-xs text-slate-600">{suggestion!.reasoning}</p>
                <p className="text-xs text-slate-400 mt-1">
                  Confidence {Math.round(suggestion!.confidence * 100)}% · maps to <span className="font-mono">{suggestion!.canonical_field}</span>
                </p>
              </TechnicalDetails>
            </div>
          )}

          {!blocked && !hasRealSuggestion && mode === "default" && (
            <div className="rounded-md bg-slate-50 border border-slate-300 p-4">
              <div className="text-sm text-slate-700">This doesn&apos;t look like a security-relevant setting to the AI.</div>
              <div className="mt-3 flex flex-wrap gap-2">
                <Button
                  variant="secondary"
                  disabled={busy}
                  onClick={() => reject("not_applicable", "Marked as not security-relevant — removed from the queue.")}
                >
                  {busy ? <Spinner className="size-4" /> : <X className="size-4" />}
                  Correct, not a security setting
                </Button>
                <Button variant="secondary" disabled={busy} onClick={() => setMode("manual")}>
                  Actually, it does — let me classify it
                </Button>
              </div>
              {suggestion?.reasoning && (
                <TechnicalDetails label="Why the AI thinks this">
                  <p className="text-xs text-slate-600">{suggestion.reasoning}</p>
                </TechnicalDetails>
              )}
            </div>
          )}

          {mode === "manual" && (
            <ManualForm
              fieldMeta={fieldMeta}
              canonicalField={canonicalField}
              value={value}
              onFieldChange={(f) => {
                setCanonicalField(f);
                // A boolean field's picker shows "Yes" first - start the value
                // there too, so what's displayed is what gets submitted.
                setValue(fieldMeta[f]?.value_kind === "bool" ? "true" : "");
              }}
              onValueChange={setValue}
              onCancel={() => setMode("default")}
              onSubmit={() => setPending({ field: canonicalField, value: coerceValue(value, fieldMeta[canonicalField]) })}
            />
          )}
        </>
      )}

      <AuditorJudgment judgment={judgment} onChange={setJudgment} disabled={busy} />

      {err && <div className="text-rose-700 text-xs">{err}</div>}

      {blocked && (
        <TechnicalDetails label="Detection detail">
          <p className="text-xs text-slate-600">
            The input-sanity gate is a deterministic keyword/pattern check, deliberately not another AI call — an
            AI-based filter would have the same injection weakness it is meant to guard against.
          </p>
        </TechnicalDetails>
      )}

      {item.similar_kb_entries && item.similar_kb_entries.length > 0 && (
        <TechnicalDetails label="Similar patterns already learned">
          <ul className="text-xs text-slate-500 space-y-0.5">
            {item.similar_kb_entries.slice(0, 3).map((s, i) => (
              <li key={i}>
                <span className="font-mono">{s.syntax_pattern}</span> → {s.canonical_field} ({s.similarity})
              </li>
            ))}
          </ul>
        </TechnicalDetails>
      )}
    </Panel>
  );
}

/** A reviewer's typed input converted to the field's declared kind, so a
 * boolean field stores `true`, not the string "true", and a number field a
 * real number - same value_kind contract the Tier-2 validator enforces. */
function coerceValue(raw: string, meta: FieldMeta | undefined): unknown {
  const v = raw.trim();
  if (!meta || meta.type === "list") return v;
  if (meta.value_kind === "bool") return v === "true";
  if (meta.value_kind === "number") {
    const n = Number(v);
    return v !== "" && !Number.isNaN(n) ? n : v;
  }
  return v;
}

function displayValue(v: unknown): string {
  if (v === true) return "Yes (enabled / true)";
  if (v === false) return "No (disabled / false)";
  return String(v);
}

/** Second, explicit confirmation before a mapping becomes a permanent
 * Tier-1 pattern. Exists because of a real incident: during a live demo a
 * reviewer picked the wrong field from the dropdown (firewall rule logging
 * instead of logging enabled), creating a valid-looking but wrong KB entry
 * that silently produced an "Unknown" on the next device. Spelling out the
 * full consequence in plain words is the cheapest guard against that. */
function ConfirmSummary({
  rawUnit,
  field,
  value,
  meta,
  busy,
  onBack,
  onConfirm,
}: {
  rawUnit: string;
  field: string;
  value: unknown;
  meta: FieldMeta | undefined;
  busy: boolean;
  onBack: () => void;
  onConfirm: () => void;
}) {
  const family = CONTROL_FAMILY_LABELS[field.split(".")[0]];
  return (
    <div className="rounded-md border-2 border-emerald-500 bg-emerald-50 p-4 space-y-3">
      <SectionLabel>Check before saving — this becomes permanent</SectionLabel>
      <div className="text-sm text-slate-800 space-y-2">
        <div>You&apos;re teaching AEGIS that this line:</div>
        <pre className="font-mono text-xs bg-white border border-emerald-200 rounded-md p-2 whitespace-pre-wrap break-words">
          {rawUnit}
        </pre>
        <div>
          sets <span className="font-semibold">{meta?.label ?? field}</span>
          {family && <span className="text-slate-500"> ({family})</span>} to{" "}
          <span className="font-semibold">{displayValue(value)}</span>.
        </div>
        {meta?.description && <div className="text-xs text-slate-600">{meta.description}</div>}
        <div className="text-xs text-slate-600">
          Every future device containing this exact line will be recognized this way automatically, with no
          further review.
        </div>
      </div>
      <div className="flex flex-wrap gap-2">
        <Button variant="success" disabled={busy} onClick={onConfirm}>
          {busy ? <Spinner className="size-4" /> : <Check className="size-4" />}
          Yes, save this
        </Button>
        <Button variant="ghost" disabled={busy} onClick={onBack}>
          <ArrowLeft className="size-4" /> Back
        </Button>
      </div>
    </div>
  );
}

/** The reviewer's own judgment, separate from WHAT the line maps to:
 * whether it matters for security at all, and why. Stored on the review
 * record and carried onto the learned pattern. Optional, never blocking. */
function AuditorJudgment({
  judgment,
  onChange,
  disabled,
}: {
  judgment: Judgment;
  onChange: (j: Judgment) => void;
  disabled: boolean;
}) {
  const options: { label: string; value: boolean | null }[] = [
    { label: "Yes", value: true },
    { label: "No", value: false },
    { label: "Not sure", value: null },
  ];
  return (
    <div className="rounded-md border border-slate-300 p-4 space-y-3">
      <SectionLabel>Auditor judgment (optional)</SectionLabel>
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-sm text-slate-700">Is this line a security-relevant setting?</span>
        <div className="inline-flex rounded-md border border-slate-300 overflow-hidden">
          {options.map((o) => {
            const active = judgment.isSecurityRelevant === o.value;
            return (
              <button
                key={o.label}
                type="button"
                disabled={disabled}
                onClick={() => onChange({ ...judgment, isSecurityRelevant: o.value })}
                className={`px-3 py-1.5 text-xs font-medium border-r border-slate-300 last:border-r-0 transition-colors ${
                  active ? "bg-slate-900 text-white" : "bg-white text-slate-600 hover:bg-slate-50"
                }`}
              >
                {o.label}
              </button>
            );
          })}
        </div>
      </div>
      <textarea
        value={judgment.notes}
        disabled={disabled}
        onChange={(e) => onChange({ ...judgment, notes: e.target.value })}
        rows={2}
        placeholder="Auditor notes — why this matters (or doesn't), anything a future reviewer should know"
        className="w-full border border-slate-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-slate-900"
      />
    </div>
  );
}

function ManualForm({
  fieldMeta,
  canonicalField,
  value,
  onFieldChange,
  onValueChange,
  onCancel,
  onSubmit,
}: {
  fieldMeta: Record<string, FieldMeta>;
  canonicalField: string;
  value: string;
  onFieldChange: (v: string) => void;
  onValueChange: (v: string) => void;
  onCancel: () => void;
  onSubmit: () => void;
}) {
  const selected = fieldMeta[canonicalField];
  // Grouped by NIST control family instead of one flat ~24-item list, so a
  // reviewer narrows by "what kind of control is this" before picking.
  const groups: Record<string, [string, FieldMeta][]> = {};
  for (const entry of Object.entries(fieldMeta)) {
    const family = entry[0].split(".")[0];
    (groups[family] ??= []).push(entry);
  }
  const isBool = selected?.type === "scalar" && selected.value_kind === "bool";
  const valueMissing = !isBool && value.trim() === "";

  return (
    <div className="rounded-md border border-slate-300 p-4 space-y-3">
      <SectionLabel>What does this actually control?</SectionLabel>
      <select
        value={canonicalField}
        onChange={(e) => onFieldChange(e.target.value)}
        className="w-full border border-slate-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-slate-900"
      >
        <option value="">— choose what this sets —</option>
        {Object.entries(groups).map(([family, entries]) => (
          <optgroup key={family} label={CONTROL_FAMILY_LABELS[family] ?? family}>
            {entries.map(([field, meta]) => (
              <option key={field} value={field}>
                {meta.label}
              </option>
            ))}
          </optgroup>
        ))}
      </select>
      {selected && (
        <div className="rounded-md bg-slate-50 border border-slate-200 p-3">
          <div className="text-sm font-medium text-slate-900">{selected.label}</div>
          <div className="text-xs text-slate-500 mt-0.5">
            {CONTROL_FAMILY_LABELS[canonicalField.split(".")[0]]} ·{" "}
            <span className="font-mono">{canonicalField}</span>
          </div>
          <p className="text-sm text-slate-700 mt-1.5">{selected.description}</p>
        </div>
      )}
      {selected && isBool && (
        <select
          value={value}
          onChange={(e) => onValueChange(e.target.value)}
          className="w-full border border-slate-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-slate-900"
        >
          <option value="true">Yes — this line turns it on / sets it to true</option>
          <option value="false">No — this line turns it off / sets it to false</option>
        </select>
      )}
      {selected && !isBool && (
        <input
          value={value}
          onChange={(e) => onValueChange(e.target.value)}
          inputMode={selected.value_kind === "number" ? "decimal" : undefined}
          placeholder={selected.value_kind === "number" ? "A number, e.g. 2 or 10" : "Value, e.g. 10.0.0.5"}
          className="w-full border border-slate-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-slate-900"
        />
      )}
      <div className="flex gap-2">
        <Button variant="success" disabled={!canonicalField || valueMissing} onClick={onSubmit}>
          <Check className="size-4" />
          Review &amp; confirm
        </Button>
        <Button variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </div>
  );
}
