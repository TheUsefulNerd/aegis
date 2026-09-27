"use client";

import { useEffect, useState } from "react";
import { BenchmarkCoverage, Stats, getCoverage, getStats } from "@/lib/api";
import { Panel, PageHeader, SectionLabel, Table, Thead, Th, Td, Tr, InlineBar, TechnicalDetails } from "@/components/ui";
import { CONFIDENCE_TIER_LABELS } from "@/lib/copy";

export default function InsightsPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [coverage, setCoverage] = useState<BenchmarkCoverage[] | null>(null);

  useEffect(() => {
    getStats()
      .then(setStats)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
    getCoverage()
      .then((c) => setCoverage(c.benchmarks))
      .catch(() => setCoverage([]));
  }, []);

  const tierRows = stats
    ? (["tier1", "tier2_accepted", "tier3_human_confirmed", "vendor_default"] as const).map((key) => ({
        key,
        label: CONFIDENCE_TIER_LABELS[key],
        value: stats.findings_by_tier[key] ?? 0,
      }))
    : [];
  const tierTotal = tierRows.reduce((s, r) => s + r.value, 0);
  const tierMax = Math.max(1, ...tierRows.map((r) => r.value));

  const sourceRows = stats ? Object.entries(stats.kb_entries_by_source) : [];
  const sourceMax = Math.max(1, ...sourceRows.map(([, v]) => v));

  return (
    <div>
      <PageHeader
        title="Insights"
        description="Deeper detail behind the Overview numbers: how compliance findings were decided, and where every learned pattern in the knowledge base came from."
      />

      {error && <Panel className="p-4 border-rose-300 bg-rose-50 text-rose-800 text-sm mb-6">{error}</Panel>}

      <div className="grid lg:grid-cols-2 gap-4">
        <Panel>
          <div className="px-5 pt-5">
            <SectionLabel>How findings were decided</SectionLabel>
            <p className="text-xs text-slate-500 mb-1">
              Every compliance finding traces back to one of three sources, never a silent guess.
            </p>
          </div>
          <Table>
            <Thead>
              <tr>
                <Th>Source</Th>
                <Th className="text-right">Findings</Th>
                <Th className="text-right">Share</Th>
                <Th></Th>
              </tr>
            </Thead>
            <tbody>
              {tierRows.map((r) => (
                <Tr key={r.key}>
                  <Td className="font-medium text-slate-900">{r.label}</Td>
                  <Td className="text-right tabular-nums">{r.value}</Td>
                  <Td className="text-right tabular-nums text-slate-500">
                    {tierTotal > 0 ? `${Math.round((r.value / tierTotal) * 100)}%` : "-"}
                  </Td>
                  <Td>
                    <InlineBar value={r.value} max={tierMax} color={r.key === "tier1" ? "emerald" : r.key === "tier2_accepted" ? "indigo" : "amber"} />
                  </Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        </Panel>

        <Panel>
          <div className="px-5 pt-5">
            <SectionLabel>Knowledge base by source</SectionLabel>
            <p className="text-xs text-slate-500 mb-1">
              Where each learned pattern came from: seed rule files, an AI classification, or a
              human confirming a new one.
            </p>
          </div>
          {sourceRows.length === 0 ? (
            <div className="text-sm text-slate-400 px-5 pb-5">none yet</div>
          ) : (
            <Table>
              <Thead>
                <tr>
                  <Th>Source</Th>
                  <Th className="text-right">Patterns</Th>
                  <Th></Th>
                </tr>
              </Thead>
              <tbody>
                {sourceRows.map(([source, count]) => (
                  <Tr key={source}>
                    <Td className="font-mono text-xs text-slate-700">{source}</Td>
                    <Td className="text-right tabular-nums">{count}</Td>
                    <Td>
                      <InlineBar value={count} max={sourceMax} />
                    </Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          )}
        </Panel>
      </div>

      {coverage && coverage.length > 0 && (
        <Panel className="mt-4">
          <div className="px-5 pt-5">
            <SectionLabel>Benchmark coverage (official DISA STIG catalogs)</SectionLabel>
            <p className="text-xs text-slate-500 mb-1">
              Each benchmark is imported in full from DISA&apos;s published release. Automated = checked by a reviewed
              rule; the rest need a manual check and are never counted as passing. A rule whose check text changes in a
              new DISA release is set aside for re-review.
            </p>
          </div>
          <Table>
            <Thead>
              <tr>
                <Th>Benchmark</Th>
                <Th>Release</Th>
                <Th className="text-right">Rules</Th>
                <Th className="text-right">Automated</Th>
                <Th className="text-right">Manual</Th>
                <Th></Th>
              </tr>
            </Thead>
            <tbody>
              {coverage.map((b) => (
                <Tr key={b.name}>
                  <Td className="font-medium text-slate-900">
                    {b.benchmark}
                    {b.needs_rereview.length > 0 && (
                      <div className="text-xs text-amber-700">{b.needs_rereview.length} changed upstream, re-review pending</div>
                    )}
                  </Td>
                  <Td className="text-xs text-slate-600">
                    {b.release}
                    {b.released ? ` (${b.released})` : ""}
                  </Td>
                  <Td className="text-right tabular-nums">{b.total}</Td>
                  <Td className="text-right tabular-nums">{b.automated}</Td>
                  <Td className="text-right tabular-nums text-slate-500">{b.manual}</Td>
                  <Td>
                    <InlineBar value={b.automated} max={b.total} color="emerald" />
                  </Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        </Panel>
      )}

      {stats && (
        <TechnicalDetails label="Raw stats payload (this replaces Prometheus/Grafana for this build; see architecture-document.md §2/§5)">
          <pre className="text-xs font-mono text-slate-600 whitespace-pre-wrap">{JSON.stringify(stats, null, 2)}</pre>
        </TechnicalDetails>
      )}
    </div>
  );
}
