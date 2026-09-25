"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Database, Clock, ShieldCheck, ScanSearch, Download, Inbox, Lock, ShieldAlert } from "lucide-react";
import { Stats, RecentConfig, getStats, getRecentConfigs, reportUrl } from "@/lib/api";
import { Panel, PageHeader, SectionLabel, KpiTile, Button, Table, Thead, Th, Td, Tr, EmptyState } from "@/components/ui";

export default function OverviewPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [recent, setRecent] = useState<RecentConfig[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    // The backend loads its embedding model on startup (10-30s+), so a page
    // load right after starting both servers can race a backend that isn't
    // listening yet - fetch() throws a bare "Failed to fetch" for that, with
    // nothing distinguishing it from the backend being genuinely down.
    // Retry through the boot window before surfacing an error.
    const MAX_ATTEMPTS = 6;
    const RETRY_DELAY_MS = 2000;

    async function load(attempt: number) {
      try {
        const [s, r] = await Promise.all([getStats(), getRecentConfigs()]);
        if (cancelled) return;
        setStats(s);
        setRecent(r);
        setError(null);
      } catch {
        if (cancelled) return;
        if (attempt < MAX_ATTEMPTS) {
          setTimeout(() => load(attempt + 1), RETRY_DELAY_MS);
          return;
        }
        setError(
          "Could not reach the AEGIS backend. Make sure it's running at " +
            "http://localhost:8000, then refresh this page."
        );
      }
    }

    load(1);
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div>
      <PageHeader
        title="Overview"
        description="How much AEGIS has learned so far, how findings were decided, and what still needs a human."
        actions={
          <Link href="/analyze">
            <Button variant="primary">
              <ScanSearch className="size-4" /> Analyze a device
            </Button>
          </Link>
        }
      />

      {error && <Panel className="p-4 border-rose-300 bg-rose-50 text-rose-800 text-sm mb-6">{error}</Panel>}

      {stats && (
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
          <KpiTile icon={ScanSearch} value={stats.devices_analyzed} label="Devices analyzed" color="slate" />
          <KpiTile icon={Database} value={stats.kb_entries_total} label="Patterns learned" color="indigo" />
          <KpiTile icon={Clock} value={stats.review_queue_pending} label="Waiting for review" color="amber" />
          <KpiTile
            icon={ShieldCheck}
            value={Object.values(stats.findings_by_tier).reduce((a, b) => a + b, 0)}
            label="Findings evaluated"
            color="emerald"
          />
          <KpiTile icon={Lock} value={stats.redactions_total ?? 0} label="Secrets hidden before AI" color="slate" />
          <KpiTile
            icon={ShieldAlert}
            value={stats.sanity_gate_blocked_total ?? 0}
            label="Injection attempts blocked"
            color={(stats.sanity_gate_blocked_total ?? 0) > 0 ? "rose" : "slate"}
          />
        </div>
      )}

      <Panel>
        <div className="px-5 pt-5">
          <SectionLabel>Recent activity</SectionLabel>
        </div>
        {recent && recent.length === 0 ? (
          <EmptyState
            icon={Inbox}
            title="No devices analyzed yet"
            description="Upload a configuration from Analyze device to see it appear here."
          />
        ) : (
          <Table>
            <Thead>
              <tr>
                <Th>Device</Th>
                <Th>Vendor</Th>
                <Th>Analyzed</Th>
                <Th>Parse coverage</Th>
                <Th className="text-right">Report</Th>
              </tr>
            </Thead>
            <tbody>
              {recent?.map((c) => (
                <Tr key={c.config_id}>
                  <Td className="font-medium text-slate-900">{c.hostname ?? "-"}</Td>
                  <Td className="font-mono text-xs">{c.vendor}</Td>
                  <Td className="text-slate-500">
                    {c.created_at ? new Date(c.created_at).toLocaleString() : "-"}
                  </Td>
                  <Td>{c.parse_coverage_pct != null ? `${c.parse_coverage_pct}%` : "-"}</Td>
                  <Td className="text-right">
                    <a
                      href={reportUrl(c.config_id)}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 hover:text-slate-900"
                    >
                      <Download className="size-3.5" /> PDF
                    </a>
                  </Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        )}
      </Panel>
    </div>
  );
}
