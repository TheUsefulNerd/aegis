// Plain-language copy for internal engineering terms. The underlying
// concepts (tiers, redaction, provenance) stay real and technically precise
// in the API/data model - this file exists so the UI can lead with language
// a non-specialist can say out loud, while the technical terms stay
// available as secondary/expandable detail for anyone (an auditor, a
// technical judge) who wants them.

// Shown per-finding, so a viewer can tell "instantly recognized" apart from
// "AI guessed" apart from "a person confirmed this" - the thing an auditor
// needs to weigh how much to trust a given PASS (architecture-document.md §5).
export const CONFIDENCE_TIER_LABELS: Record<string, string> = {
  tier1: "Instantly recognized",
  tier2_accepted: "AI-classified",
  tier3_human_confirmed: "Human-confirmed",
};

// Mirrors backend/app/canonical_schema.py's CONTROL_FAMILIES - the prefix of
// every canonical field code ("AC.telnet_enabled" -> "AC").
export const CONTROL_FAMILY_LABELS: Record<string, string> = {
  AC: "Access Control",
  AU: "Audit and Accountability",
  IA: "Identification and Authentication",
  SC: "System and Communications Protection",
  CM: "Configuration Management",
};

// One entry per rule in backend/app/redaction.py's _RULES - keep in sync.
// `label` is the short noun phrase; `explanation` is the one line a security
// manager reads to understand what shape of thing gets caught.
export const REDACTION_TYPE_INFO: Record<string, { label: string; explanation: string }> = {
  TYPE7_PASSWORD: {
    label: "Encoded password (Cisco type 7)",
    explanation: "A 'password 7' value. Type 7 is reversible encoding, not encryption: anyone can decode it, so it's treated as a plain-text password.",
  },
  ENABLE_SECRET_HASH: {
    label: "Admin password hash",
    explanation: "The hash from an 'enable secret' line. The hash type digit stays visible (compliance rules need it); only the hash itself is removed.",
  },
  USER_SECRET_HASH: {
    label: "Local user password hash",
    explanation: "The hash from a 'username … secret' line (or EOS 'aaa root secret'). The hash type stays visible; the hash itself is removed.",
  },
  CLI_PASSWORD: {
    label: "Plain or weakly-encoded password",
    explanation: "A password typed directly into the config: 'enable password', 'username … password 0', a line password, FTP or BGP neighbor passwords.",
  },
  SNMPV3_SECRET: {
    label: "SNMPv3 auth/privacy password",
    explanation: "The authentication or encryption passphrase of an SNMPv3 user.",
  },
  ROUTING_AUTH_KEY: {
    label: "Routing protocol key",
    explanation: "A key that authenticates routing neighbors (key-chain key-string, OSPF authentication/message-digest keys).",
  },
  SNMP_COMMUNITY: {
    label: "SNMP community string",
    explanation: "Works like a password for SNMP monitoring. Defaults like 'public'/'private' are left visible on purpose so they can still be flagged as non-compliant.",
  },
  PRE_SHARED_KEY: {
    label: "VPN / IPsec pre-shared key",
    explanation: "The shared key that authenticates a VPN tunnel.",
  },
  AAA_KEY: {
    label: "RADIUS / TACACS+ shared secret",
    explanation: "The secret a device uses to talk to its central login server.",
  },
  GENERIC_SECRET_FIELD: {
    label: "Secret-looking value",
    explanation: "Any 'password=', 'secret:', 'psk=' or 'shared_key=' style value, in CLI or JSON-style configs.",
  },
  XML_ELEMENT_SECRET: {
    label: "Secret inside an XML element",
    explanation: "A value inside an XML tag whose name contains password, secret, psk or shared_key (e.g. <password>…</password>).",
  },
};

export function redactionLabel(type: string): string {
  return REDACTION_TYPE_INFO[type]?.label ?? type;
}
