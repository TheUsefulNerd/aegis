const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export type IngestResult = {
  device_id: string;
  config_id: string;
  vendor: string;
  format: string;
  fingerprint_confidence: string;
  total_units: number;
  tier_counts: { tier1: number; tier2_accepted: number; tier3_pending: number };
  parse_coverage_pct: number;
  redaction_hits: { type: string; count: number }[];
  redaction_examples: { type: string; unit: string }[];
  sanity_gate_hits: { unit: string; reason: string; pattern: string }[];
  hostname: string | null;
  fields: Record<string, unknown>;
  pending_review_ids: string[];
};

export type ReviewQueueItem = {
  id: string;
  raw_unit: string;
  context: string | null;
  candidate_mapping: {
    canonical_field: string;
    value: unknown;
    confidence: number;
    reasoning: string;
  } | null;
  similar_kb_entries: { syntax_pattern: string; canonical_field: string; similarity: number }[] | null;
  confidence: number | null;
  status: string;
  flag_type: "sanity_gate" | null;
  flag_reason: string | null;
  device_hostname: string | null;
  device_vendor: string | null;
  created_at: string | null;
};

export type Stats = {
  kb_entries_total: number;
  kb_entries_by_source: Record<string, number>;
  review_queue_pending: number;
  findings_by_tier: Record<string, number>;
  devices_analyzed: number;
  sanity_gate_blocked_total: number;
  redactions_total: number;
  redactions_by_type: Record<string, number>;
};

async function handle<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`API error ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

export async function ingestConfig(file: File): Promise<IngestResult> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${API_BASE}/ingest`, { method: "POST", body: form });
  return handle<IngestResult>(res);
}

export async function listReviewQueue(status = "pending"): Promise<ReviewQueueItem[]> {
  const res = await fetch(`${API_BASE}/review-queue?status=${status}`);
  return handle<ReviewQueueItem[]>(res);
}

export async function confirmReviewItem(
  id: string,
  body: {
    canonical_field: string;
    value: unknown;
    reviewer_id: string;
    pattern_type: "exact" | "regex";
    syntax_pattern?: string;
    is_security_relevant?: boolean | null;
    reviewer_notes?: string | null;
  }
) {
  const res = await fetch(`${API_BASE}/review-queue/${id}/confirm`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return handle<{ kb_entry_id: string; review_queue_id: string; status: string }>(res);
}

export async function rejectReviewItem(id: string, body: { reviewer_id: string; reason?: string; reviewer_notes?: string | null }) {
  const res = await fetch(`${API_BASE}/review-queue/${id}/reject`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return handle<{ review_queue_id: string; status: string }>(res);
}

export async function getStats(): Promise<Stats> {
  const res = await fetch(`${API_BASE}/stats`);
  return handle<Stats>(res);
}

export type FieldMeta = {
  type: "scalar" | "list";
  value_kind?: "bool" | "number" | "string";
  label: string;
  description: string;
};

export async function getCanonicalFields(): Promise<Record<string, FieldMeta>> {
  const res = await fetch(`${API_BASE}/canonical-fields`);
  return handle<Record<string, FieldMeta>>(res);
}

export type ConfidenceTier = "tier1" | "tier2_accepted" | "tier3_human_confirmed" | null;

export type Finding = {
  rule_id: string;
  title: string | null;
  framework: string;
  control_family: string;
  severity: string;
  result: "PASS" | "FAIL" | "NOT_EVALUATED";
  confidence_tier: ConfidenceTier;
  evidence: Record<string, unknown>;
  remediation: string | null;
  remediation_source: string | null;
};

export type EvaluateResult = {
  config_id: string;
  device_id: string;
  vendor: string;
  counts: { PASS: number; FAIL: number; NOT_EVALUATED: number };
  counts_by_severity: Record<string, { PASS: number; FAIL: number; NOT_EVALUATED: number }>;
  findings: Finding[];
};

export async function getFrameworks(): Promise<string[]> {
  const res = await fetch(`${API_BASE}/frameworks`);
  return handle<string[]>(res);
}

export async function evaluateConfig(configId: string, framework?: string): Promise<EvaluateResult> {
  const qs = framework ? `?framework=${encodeURIComponent(framework)}` : "";
  const res = await fetch(`${API_BASE}/configs/${configId}/evaluate${qs}`, { method: "POST" });
  return handle<EvaluateResult>(res);
}

export function reportUrl(configId: string, framework?: string): string {
  const params = new URLSearchParams();
  if (framework) params.set("framework", framework);
  // Browser-detected IANA zone only (e.g. "Asia/Kolkata") - no IP/location
  // lookup - so the PDF's timestamps match the viewer's own clock.
  try {
    params.set("tz", Intl.DateTimeFormat().resolvedOptions().timeZone);
  } catch {
    // Intl unsupported in this environment - backend falls back to IST.
  }
  const qs = params.toString();
  return `${API_BASE}/configs/${configId}/report.pdf${qs ? `?${qs}` : ""}`;
}

/** The report endpoint now serves `Content-Disposition: inline` so it can be
 * embedded in an <iframe> preview; this forces a real save-to-disk
 * regardless of that header, by fetching the bytes ourselves. */
export async function downloadPdf(url: string, filename: string) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`API error ${res.status}`);
  const blob = await res.blob();
  const objectUrl = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = objectUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(objectUrl);
}

export type RecentConfig = {
  config_id: string;
  device_id: string;
  hostname: string | null;
  vendor: string;
  created_at: string | null;
  parse_coverage_pct: number | null;
};

export async function getRecentConfigs(limit = 8): Promise<RecentConfig[]> {
  const res = await fetch(`${API_BASE}/configs?limit=${limit}`);
  return handle<RecentConfig[]>(res);
}
