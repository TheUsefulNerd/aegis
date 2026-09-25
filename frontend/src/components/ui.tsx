"use client";

import { ChevronDown, Cpu, Sparkles, UserCheck, Check, CheckCircle2, XCircle } from "lucide-react";
import { ReactNode, useEffect, useState } from "react";

/* Design language: enterprise console, not marketing page.
 * - Borders carry real contrast (slate-300, not slate-200) plus a light
 *   shadow, so adjacent panels are unmistakably separate surfaces - the
 *   thing that was missing when everything was near-white on near-white.
 * - rounded-md (6px) everywhere except the outermost panel (rounded-lg) -
 *   one radius scale, used consistently.
 */

export function Panel({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-lg border border-slate-300 bg-white shadow-sm ${className}`}>
      {children}
    </div>
  );
}

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-4 pb-6 mb-6 border-b border-slate-300">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-slate-900">{title}</h1>
        {description && <p className="text-sm text-slate-500 mt-1 max-w-2xl">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
    </div>
  );
}

export function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <div className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-2">
      {children}
    </div>
  );
}

/** The AEGIS shield mark - a plain inline SVG (not an icon font) so it
 * renders identically in the sidebar, a report, or anywhere else it's
 * dropped in, at any size via the `size` prop. */
export function Logo({ size = 22, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className} aria-hidden="true">
      <path d="M12 2l8 3v6c0 5-3.4 8.4-8 11-4.6-2.6-8-6-8-11V5l8-3z" fill="currentColor" />
      <path
        d="M8.5 12.2l2.2 2.2 4.3-4.7"
        stroke="white"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />
    </svg>
  );
}

type ButtonVariant = "primary" | "success" | "secondary" | "ghost" | "danger";

const BUTTON_STYLES: Record<ButtonVariant, string> = {
  primary: "bg-slate-900 text-white hover:bg-slate-800 disabled:bg-slate-300 shadow-sm",
  success: "bg-emerald-600 text-white hover:bg-emerald-700 disabled:bg-emerald-300 shadow-sm",
  secondary: "bg-white text-slate-700 border border-slate-300 hover:bg-slate-50 disabled:text-slate-400",
  ghost: "text-slate-500 hover:text-slate-800 hover:bg-slate-100 disabled:text-slate-300",
  danger: "bg-white text-rose-700 border border-rose-300 hover:bg-rose-50 disabled:text-rose-300",
};

export function Button({
  children,
  variant = "secondary",
  className = "",
  ...props
}: {
  children: ReactNode;
  variant?: ButtonVariant;
  className?: string;
} & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      className={`inline-flex items-center gap-1.5 rounded-md px-3.5 py-2 text-sm font-medium transition-colors disabled:cursor-not-allowed focus:outline-none focus-visible:ring-2 focus-visible:ring-slate-900 focus-visible:ring-offset-1 ${BUTTON_STYLES[variant]} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}

export function Badge({
  children,
  color = "slate",
}: {
  children: ReactNode;
  color?: "slate" | "emerald" | "indigo" | "amber" | "rose";
}) {
  const colors = {
    slate: "bg-slate-100 text-slate-700 ring-1 ring-inset ring-slate-300",
    emerald: "bg-emerald-50 text-emerald-700 ring-1 ring-inset ring-emerald-300",
    indigo: "bg-indigo-50 text-indigo-700 ring-1 ring-inset ring-indigo-300",
    amber: "bg-amber-50 text-amber-800 ring-1 ring-inset ring-amber-300",
    rose: "bg-rose-50 text-rose-700 ring-1 ring-inset ring-rose-300",
  };
  return (
    <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ${colors[color]}`}>
      {children}
    </span>
  );
}

/** Who/what produced a value: an exact deterministic pattern match, an AI
 * classification, or a human confirmation. Same three states everywhere
 * (findings table, PDF "Source" column, review queue) so a viewer only has
 * to learn this vocabulary once. */
const SOURCE_META: Record<string, { icon: typeof Cpu; color: "emerald" | "indigo" | "amber"; label: string }> = {
  tier1: { icon: Cpu, color: "emerald", label: "Deterministic" },
  tier2_accepted: { icon: Sparkles, color: "indigo", label: "AI-classified" },
  tier3_human_confirmed: { icon: UserCheck, color: "amber", label: "Human-confirmed" },
};

export function SourceBadge({ tier }: { tier: string | null | undefined }) {
  const meta = tier ? SOURCE_META[tier] : undefined;
  if (!meta) return <span className="text-xs text-slate-400">—</span>;
  const Icon = meta.icon;
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600">
      <Icon className="size-3.5" />
      {meta.label}
    </span>
  );
}

export type StepState = "done" | "active" | "upcoming";

/** Horizontal progress trail that doubles as a tab strip: each step is
 * clickable once it's reachable ("done" or "active"), so the four pipeline
 * stages (upload → understand → check → report) are real tab panes, not one
 * long scrolling page. */
export function PipelineTrail({
  steps,
  activeIndex,
  onSelect,
}: {
  steps: { label: string; state: StepState }[];
  activeIndex?: number;
  onSelect?: (index: number) => void;
}) {
  return (
    <div className="flex items-center w-full overflow-x-auto">
      {steps.map((step, i) => {
        const reachable = step.state !== "upcoming";
        const isActive = activeIndex === i;
        return (
          <div key={step.label} className="flex items-center flex-1 min-w-[110px] last:flex-none">
            <button
              type="button"
              disabled={!reachable || !onSelect}
              onClick={() => onSelect?.(i)}
              className={`flex flex-col items-center gap-1.5 text-center group ${
                reachable && onSelect ? "cursor-pointer" : "cursor-default"
              }`}
            >
              <div
                className={`flex items-center justify-center size-6 rounded-full text-[11px] font-semibold shrink-0 transition-shadow ${
                  step.state === "done"
                    ? "bg-emerald-600 text-white"
                    : step.state === "active"
                    ? "bg-slate-900 text-white"
                    : "bg-slate-100 text-slate-400"
                } ${isActive ? "ring-2 ring-offset-2 ring-slate-900" : ""}`}
              >
                {step.state === "done" ? <Check className="size-3.5" /> : i + 1}
              </div>
              <span
                className={`text-xs font-medium whitespace-nowrap ${
                  step.state === "upcoming" ? "text-slate-400" : "text-slate-700"
                } ${reachable && onSelect ? "group-hover:text-slate-950" : ""} ${isActive ? "font-semibold" : ""}`}
              >
                {step.label}
              </span>
            </button>
            {i < steps.length - 1 && (
              <div className={`h-px flex-1 mx-2 ${step.state === "done" ? "bg-emerald-300" : "bg-slate-300"}`} />
            )}
          </div>
        );
      })}
    </div>
  );
}

export function KpiTile({
  icon: Icon,
  value,
  label,
  color = "slate",
}: {
  icon: typeof Cpu;
  value: string | number;
  label: string;
  color?: "indigo" | "emerald" | "amber" | "slate" | "rose";
}) {
  const tint = {
    indigo: "text-indigo-600",
    emerald: "text-emerald-600",
    amber: "text-amber-600",
    slate: "text-slate-500",
    rose: "text-rose-600",
  }[color];
  return (
    <Panel className="p-4">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-slate-500">{label}</span>
        <Icon className={`size-4 ${tint}`} />
      </div>
      <div className="text-2xl font-semibold tabular-nums mt-2 text-slate-900">{value}</div>
    </Panel>
  );
}

/** A thin magnitude bar meant to sit inside a table cell alongside its
 * number - a supplementary visual cue, not a replacement for the table. */
export function InlineBar({ value, max, color = "slate" }: { value: number; max: number; color?: "slate" | "emerald" | "indigo" | "amber" }) {
  const pct = max > 0 ? Math.max(2, Math.round((value / max) * 100)) : 0;
  const bg = { slate: "bg-slate-600", emerald: "bg-emerald-500", indigo: "bg-indigo-500", amber: "bg-amber-500" }[color];
  return (
    <div className="w-24 h-1.5 rounded-full bg-slate-200 overflow-hidden">
      <div className={`h-full rounded-full ${bg}`} style={{ width: `${pct}%` }} />
    </div>
  );
}

/* --- Table primitives: real tabular data used throughout (findings,
 * insights breakdowns, review queue) instead of one big card per row. Header
 * has a visible tint + a 2px rule, rows zebra-stripe automatically, so
 * adjacent rows/cells are easy to tell apart at a glance. --- */

export function Table({ children }: { children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm border-collapse [&_tbody_tr:nth-child(even)]:bg-slate-50">{children}</table>
    </div>
  );
}

export function Thead({ children }: { children: ReactNode }) {
  return <thead className="bg-slate-50 border-b-2 border-slate-300">{children}</thead>;
}

export function Th({ children, className = "" }: { children?: ReactNode; className?: string }) {
  return (
    <th className={`text-left font-semibold text-xs uppercase tracking-wide text-slate-600 px-3 py-2.5 ${className}`}>
      {children}
    </th>
  );
}

export function Td({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <td className={`px-3 py-3 align-top text-slate-700 ${className}`}>{children}</td>;
}

export function Tr({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <tr className={`border-b border-slate-200 last:border-0 hover:bg-slate-100/70 transition-colors ${className}`}>{children}</tr>;
}

export function EmptyState({ icon: Icon, title, description }: { icon: typeof Cpu; title: string; description?: string }) {
  return (
    <div className="flex flex-col items-center justify-center text-center py-12 px-6">
      <div className="rounded-full bg-slate-100 p-3 mb-3">
        <Icon className="size-5 text-slate-400" />
      </div>
      <div className="text-sm font-medium text-slate-700">{title}</div>
      {description && <div className="text-xs text-slate-500 mt-1 max-w-xs">{description}</div>}
    </div>
  );
}

/** Progressive disclosure for internal/technical detail. Collapsed by
 * default so the plain-language view stays primary, but styled as its own
 * bordered, tinted row (not a tiny gray link) so an auditor or technical
 * judge actually notices it's there. */
export function TechnicalDetails({ children, label = "Technical & audit details" }: { children: ReactNode; label?: string }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-md border border-slate-300 bg-slate-50 mt-4 overflow-hidden">
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between gap-2 px-4 py-2.5 text-sm font-medium text-slate-700 hover:bg-slate-100 transition-colors"
      >
        <span className="flex items-center gap-2">
          <ChevronDown className={`size-4 transition-transform ${open ? "rotate-180" : ""}`} />
          {label}
        </span>
        <span className="text-xs text-slate-400">{open ? "Hide" : "Show"}</span>
      </button>
      {open && <div className="px-4 pb-4 pt-1 border-t border-slate-200 bg-white">{children}</div>}
    </div>
  );
}

/** Lightweight inline success/error feedback for an action that would
 * otherwise resolve silently (e.g. a review-queue item just disappearing
 * with no confirmation that anything actually happened). Auto-dismisses. */
export function InlineToast({
  toast,
}: {
  toast: { type: "success" | "error"; text: string } | null;
}) {
  if (!toast) return null;
  const isSuccess = toast.type === "success";
  return (
    <div
      className={`flex items-center gap-2 rounded-md border px-4 py-2.5 text-sm font-medium mb-4 ${
        isSuccess ? "bg-emerald-50 border-emerald-300 text-emerald-800" : "bg-rose-50 border-rose-300 text-rose-800"
      }`}
    >
      {isSuccess ? <CheckCircle2 className="size-4 shrink-0" /> : <XCircle className="size-4 shrink-0" />}
      {toast.text}
    </div>
  );
}

/** Hook for InlineToast: shows a message for `ms`, then clears itself. */
export function useToast(ms = 3000) {
  const [toast, setToast] = useState<{ type: "success" | "error"; text: string } | null>(null);
  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), ms);
    return () => clearTimeout(t);
  }, [toast, ms]);
  return [toast, setToast] as const;
}

export function Spinner({ className = "" }: { className?: string }) {
  return (
    <svg className={`animate-spin ${className}`} viewBox="0 0 24 24" fill="none">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
    </svg>
  );
}
