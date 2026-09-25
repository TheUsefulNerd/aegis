import { Mail, ShieldCheck } from "lucide-react";
import { Panel, PageHeader, SectionLabel, Badge } from "@/components/ui";

// Only the lead's details are confirmed; the other five roles are named per
// the SIH problem statement's team composition (1 cybersecurity specialist +
// 4 AI/SWE engineers) without inventing names - update this array with real
// names/emails once the team confirms them.
const TEAM = [
  { name: "Advait", role: "Team Lead, Full-stack & AI", email: "advait@eligere.ai", confirmed: true },
  { name: "To be added", role: "Cybersecurity Specialist", email: null, confirmed: false },
  { name: "To be added", role: "AI / Software Engineer", email: null, confirmed: false },
  { name: "To be added", role: "AI / Software Engineer", email: null, confirmed: false },
  { name: "To be added", role: "AI / Software Engineer", email: null, confirmed: false },
  { name: "To be added", role: "AI / Software Engineer", email: null, confirmed: false },
];

export default function ContactPage() {
  return (
    <div>
      <PageHeader
        title="Contact us"
        description="AEGIS is built by a 6-person team for Smart India Hackathon 2026, under the NTRO network-compliance problem statement."
      />

      <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {TEAM.map((member, i) => (
          <Panel key={i} className="p-5">
            <div className="flex items-start justify-between gap-2">
              <div>
                <div className="font-semibold text-slate-900">{member.name}</div>
                <div className="text-sm text-slate-500 mt-0.5">{member.role}</div>
              </div>
              {member.confirmed ? (
                <Badge color="emerald">Lead</Badge>
              ) : (
                <Badge color="slate">Pending</Badge>
              )}
            </div>
            {member.email && (
              <a
                href={`mailto:${member.email}`}
                className="mt-3 inline-flex items-center gap-1.5 text-sm font-medium text-slate-700 hover:text-slate-900"
              >
                <Mail className="size-3.5" /> {member.email}
              </a>
            )}
          </Panel>
        ))}
      </div>

      <Panel className="p-5 mt-4 flex items-start gap-3">
        <ShieldCheck className="size-5 text-slate-500 shrink-0 mt-0.5" />
        <div className="text-sm text-slate-600">
          <SectionLabel>About this build</SectionLabel>
          For general questions about AEGIS or this submission, reach the team lead directly at{" "}
          <a href="mailto:advait@eligere.ai" className="font-medium text-slate-900 hover:underline">
            advait@eligere.ai
          </a>
          .
        </div>
      </Panel>
    </div>
  );
}
