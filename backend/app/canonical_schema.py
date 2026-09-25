"""Canonical Security Baseline Model - starter field set, organized around
NIST 800-53 control families per architecture-document.md §3 step 5. This
grows as rule authoring (cybersecurity teammate) covers more controls - this
is the Day-1 minimum needed to get the three demo devices' chosen controls
end-to-end.

Each field carries a human-readable label + description alongside its code.
This exists because the review-queue UI is meant to be usable by someone who
doesn't already know NIST control-family naming - the label/description are
what render there; the code (e.g. "IA.ssh_version") stays visible as
secondary detail for anyone who does want the technical mapping (an auditor,
or the rule engine itself).
"""

# family prefix -> meaning, for reference / for the technical-detail view
CONTROL_FAMILIES = {
    "AC": "Access Control",
    "AU": "Audit and Accountability",
    "IA": "Identification and Authentication",
    "SC": "System and Communications Protection",
    "CM": "Configuration Management",
}

FIELD_METADATA = {
    "AC.telnet_enabled": {
        "type": "scalar",
        "value_kind": "bool",
        "label": "Telnet access",
        "description": "Whether unencrypted Telnet remote-access is enabled on this device.",
    },
    "IA.ssh_version": {
        "type": "scalar",
        "value_kind": "number",
        "label": "SSH version",
        "description": "Which version of SSH is required for encrypted remote access (should be 2, not 1).",
    },
    "IA.password_encryption_enabled": {
        "type": "scalar",
        "value_kind": "bool",
        "label": "Password encryption",
        "description": "Whether stored passwords/secrets in the config are encrypted rather than plain text.",
    },
    "AU.logging_enabled": {
        "type": "scalar",
        "value_kind": "bool",
        "label": "Logging enabled",
        "description": "Whether administrative activity logging is turned on.",
    },
    "AU.logging_host": {
        "type": "list",
        "label": "Remote logging server",
        "description": "Address(es) of the remote server(s) logs are sent to, for audit trail purposes.",
    },
    "AC.acl_rules": {
        "type": "list",
        "label": "Access control rules",
        "description": "Firewall/ACL rules controlling what traffic is allowed or denied.",
    },
    "SC.enabled_ciphers": {
        "type": "list",
        "label": "Allowed encryption ciphers",
        "description": "Which cryptographic cipher suites this device is configured to accept.",
    },
    "AC.privileged_password_type": {
        "type": "scalar",
        "value_kind": "string",
        "label": "Privileged access password type",
        "description": "How the privileged (enable) password is protected - e.g. a strong hashed 'enable secret' vs a weaker/plaintext 'enable password'.",
    },
    "AC.session_idle_timeout_minutes": {
        "type": "scalar",
        "value_kind": "number",
        "label": "Session idle timeout",
        "description": "How many minutes an idle administrative session is left open before being disconnected.",
    },
    "AC.snmp_community_strings": {
        "type": "list",
        "label": "SNMP community strings",
        "description": "SNMP community strings configured on this device (should never be a default like 'public' or 'private').",
    },
    "AC.login_banner_configured": {
        "type": "scalar",
        "value_kind": "bool",
        "label": "Login banner",
        "description": "Whether a legal/warning banner is shown before a user logs in.",
    },
    "AC.vty_access_class": {
        "type": "scalar",
        "value_kind": "bool",
        "label": "VTY management restriction",
        "description": "Whether remote-management (VTY) lines are restricted to specific hosts/networks via an access-class.",
    },
    "AU.log_access_restricted": {
        "type": "scalar",
        "value_kind": "bool",
        "label": "Log access restricted",
        "description": "Whether access to stored audit logs and logging configuration is itself restricted to authorized administrators.",
    },
    "AU.ntp_authentication_enabled": {
        "type": "scalar",
        "value_kind": "bool",
        "label": "NTP authentication",
        "description": "Whether time-sync (NTP) messages are cryptographically authenticated, preventing a spoofed time source from skewing logs/certs.",
    },
    "SC.ip_source_routing_enabled": {
        "type": "scalar",
        "value_kind": "bool",
        "label": "IP source routing",
        "description": "Whether the device honors source-routed packets (attacker-specified paths) - should be disabled.",
    },
    "SC.proxy_arp_enabled": {
        "type": "scalar",
        "value_kind": "bool",
        "label": "Proxy ARP",
        "description": "Whether the device answers ARP requests on behalf of other hosts - normally should be disabled on external-facing interfaces.",
    },
    "SC.pad_enabled": {
        "type": "scalar",
        "value_kind": "bool",
        "label": "PAD service",
        "description": "Whether the legacy Packet Assembler/Disassembler (X.25) service is enabled - should be disabled if unused.",
    },
    "SC.webgui_protocol": {
        "type": "scalar",
        "value_kind": "bool",
        "label": "Web management protocol",
        "description": "Whether the device's web-based admin interface enforces HTTPS (true) rather than allowing plain HTTP (false).",
    },
    "AU.firewall_rule_logging": {
        "type": "scalar",
        "value_kind": "bool",
        "label": "Firewall rule logging",
        "description": "Whether individual firewall/filter rules are configured to log matching traffic.",
    },
    "SC.routing_authentication": {
        "type": "scalar",
        "value_kind": "bool",
        "label": "Routing protocol authentication",
        "description": "Whether routing-protocol neighbor sessions require cryptographic authentication.",
    },
    "SC.control_plane_protection": {
        "type": "scalar",
        "value_kind": "bool",
        "label": "Control plane protection",
        "description": "Whether Control Plane Policing/Protection is configured to shield the device's own management/routing processes from excessive or unauthorized traffic.",
    },
    "SC.ipv6_ra_suppression": {
        "type": "scalar",
        "value_kind": "bool",
        "label": "IPv6 router advertisement suppression",
        "description": "Whether the device is configured to suppress outgoing IPv6 Router Advertisements on external-facing interfaces.",
    },
    "SC.external_interface_cdp": {
        "type": "scalar",
        "value_kind": "bool",
        "label": "CDP on external interfaces",
        "description": "Whether Cisco Discovery Protocol is enabled on interfaces facing outside the organization's network (should be disabled - CDP leaks device details to anything listening).",
    },
    "SC.network_segmentation": {
        "type": "scalar",
        "value_kind": "bool",
        "label": "Network segmentation",
        "description": "Whether security-sensitive networks/systems are logically separated (VLANs, zones, ACLs) rather than sharing one flat network.",
    },
}

# Pseudo-field for KB patterns that mean "this line is not a security
# setting". Deliberately NOT in FIELD_METADATA: the AI validator can never
# emit it and the review-queue picker never offers it - it only comes from
# the deterministic not-security seeds or a human's "not security-relevant"
# decision.
NOT_SECURITY = "NOT_SECURITY"

# Back-compat: field -> value type, used by resolve.py / llm_client.py.
CANONICAL_FIELDS = {field: meta["type"] for field, meta in FIELD_METADATA.items()}


def is_valid_field(name: str) -> bool:
    return name in FIELD_METADATA


def label_for(name: str) -> str:
    meta = FIELD_METADATA.get(name)
    return meta["label"] if meta else name
