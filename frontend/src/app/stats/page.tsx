"use client";

import { useEffect, useState } from "react";
import { Stats, getStats } from "@/lib/api";
import { Panel, PageHeader, SectionLabel, Table, Thead, Th, Td, Tr, InlineBar, TechnicalDetails } from "@/components/ui";
import { CONFIDENCE_TIER_LABELS } from "@/lib/copy";

export default function InsightsPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getStats()
      .then(setStats)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  const tierRows = stats
    ? (["tier1", "tier2_accepted", "tier3_human_confirmed"] as const).map((key) => ({
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

      {stats && (
        <TechnicalDetails label="Raw stats payload (this replaces Prometheus/Grafana for this build; see architecture-document.md §2/§5)">
          <pre className="text-xs font-mono text-slate-600 whitespace-pre-wrap">{JSON.stringify(stats, null, 2)}</pre>
        </TechnicalDetails>
      )}
    </div>
  );
}
