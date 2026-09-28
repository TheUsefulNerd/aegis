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

# "insecure" (bool fields) / "worse" (number fields): the direction that is
# LESS secure. When one config sets the same field more than once (two
# `line vty` blocks, one with telnet and one without), the least secure
# value is the device's real posture - a last-line-wins merge once passed a
# telnet check because the second VTY block said ssh.
FIELD_METADATA = {
    "AC.telnet_enabled": {
        "type": "scalar",
        "value_kind": "bool",
        "insecure": True,
        "label": "Telnet access",
        "description": "Whether unencrypted Telnet remote-access is enabled on this device.",
    },
    "IA.ssh_version": {
        "type": "scalar",
        "value_kind": "number",
        "worse": "lower",
        "label": "SSH version",
        "description": "Which version of SSH is required for encrypted remote access (should be 2, not 1).",
    },
    "IA.password_encryption_enabled": {
        "type": "scalar",
        "value_kind": "bool",
        "insecure": False,
        "label": "Password encryption",
        "description": "Whether stored passwords/secrets in the config are encrypted rather than plain text.",
    },
    "AU.logging_enabled": {
        "type": "scalar",
        "value_kind": "bool",
        "insecure": False,
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
        # Least secure first: a type-7 `enable password` next to an `enable
        # secret 9` still counts, whichever line comes first (second review).
        "ranked": ["enable_password", "secret_type_5", "secret_type_8", "secret_type_9"],
        "label": "Privileged access password type",
        "description": "How the privileged (enable) password is protected - e.g. a strong hashed 'enable secret' vs a weaker/plaintext 'enable password'.",
    },
    "AC.session_idle_timeout_minutes": {
        "type": "scalar",
        "value_kind": "number",
        "worse": "higher_or_zero",
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
        "insecure": False,
        "label": "Login banner",
        "description": "Whether a legal/warning banner is shown before a user logs in.",
    },
    "AC.vty_access_class": {
        "type": "scalar",
        "value_kind": "bool",
        "insecure": False,
        "label": "VTY management restriction",
        "description": "Whether remote-management (VTY) lines are restricted to specific hosts/networks via an access-class.",
    },
    "AU.log_access_restricted": {
        "type": "scalar",
        "value_kind": "bool",
        "insecure": False,
        "label": "Log access restricted",
        "description": "Whether access to stored audit logs and logging configuration is itself restricted to authorized administrators.",
    },
    "AU.ntp_keys_configured": {
        "type": "scalar",
        "value_kind": "bool",
        "insecure": False,
        "label": "NTP keys configured",
        "description": "Whether NTP authentication has a key, a trusted key and at least one server that uses a key.",
    },
    "AU.ntp_authentication_enabled": {
        "type": "scalar",
        "value_kind": "bool",
        "insecure": False,
        "label": "NTP authentication",
        "description": "Whether time-sync (NTP) messages are cryptographically authenticated, preventing a spoofed time source from skewing logs/certs.",
    },
    "SC.ip_source_routing_enabled": {
        "type": "scalar",
        "value_kind": "bool",
        "insecure": True,
        "label": "IP source routing",
        "description": "Whether the device honors source-routed packets (attacker-specified paths) - should be disabled.",
    },
    "SC.proxy_arp_enabled": {
        "type": "scalar",
        "value_kind": "bool",
        "insecure": True,
        "label": "Proxy ARP",
        "description": "Whether the device answers ARP requests on behalf of other hosts - normally should be disabled on external-facing interfaces.",
    },
    "SC.pad_enabled": {
        "type": "scalar",
        "value_kind": "bool",
        "insecure": True,
        "label": "PAD service",
        "description": "Whether the legacy Packet Assembler/Disassembler (X.25) service is enabled - should be disabled if unused.",
    },
    "SC.webgui_protocol": {
        "type": "scalar",
        "value_kind": "bool",
        "insecure": False,
        "label": "Web management protocol",
        "description": "Whether the device's web-based admin interface enforces HTTPS (true) rather than allowing plain HTTP (false).",
    },
    "AU.firewall_rule_logging": {
        "type": "scalar",
        "value_kind": "bool",
        "insecure": False,
        "label": "Firewall rule logging",
        "description": "Whether individual firewall/filter rules are configured to log matching traffic.",
    },
    "SC.routing_authentication": {
        "type": "scalar",
        "value_kind": "bool",
        "insecure": False,
        "label": "Routing protocol authentication",
        "description": "Whether routing-protocol neighbor sessions require cryptographic authentication.",
    },
    "SC.control_plane_protection": {
        "type": "scalar",
        "value_kind": "bool",
        "insecure": False,
        "label": "Control plane protection",
        "description": "Whether Control Plane Policing/Protection is configured to shield the device's own management/routing processes from excessive or unauthorized traffic.",
    },
    "SC.ipv6_ra_suppression": {
        "type": "scalar",
        "value_kind": "bool",
        "insecure": False,
        "label": "IPv6 router advertisement suppression",
        "description": "Whether the device is configured to suppress outgoing IPv6 Router Advertisements on external-facing interfaces.",
    },
    "SC.external_interface_cdp": {
        "type": "scalar",
        "value_kind": "bool",
        "insecure": True,
        "label": "CDP on external interfaces",
        "description": "Whether Cisco Discovery Protocol is enabled on interfaces facing outside the organization's network (should be disabled - CDP leaks device details to anything listening).",
    },
    "SC.network_segmentation": {
        "type": "scalar",
        "value_kind": "bool",
        "insecure": False,
        "label": "Network segmentation",
        "description": "Whether security-sensitive networks/systems are logically separated (VLANs, zones, ACLs) rather than sharing one flat network.",
    },
    # Added 2026-09-27 for the imported DISA STIG catalogs (rules/stig_catalog_map.yaml).
    "AU.admin_event_logging": {
        "type": "scalar",
        "value_kind": "bool",
        "insecure": False,
        "label": "Admin event logging",
        "description": "Whether the device records administrative and system events (account changes, privilege changes, logons) as audit records.",
    },
    "AC.login_max_failed_attempts": {
        "type": "scalar",
        "value_kind": "number",
        "worse": "higher_or_zero",
        "label": "Failed logon attempts before lockout",
        "description": "How many consecutive invalid logon attempts are allowed before the device blocks further logons (0 = no enforced lockout).",
    },
    "AU.ntp_servers": {
        "type": "list",
        "label": "NTP servers",
        "description": "The time servers the device synchronizes its clock with.",
    },
    "IA.password_policy_enabled": {
        "type": "scalar",
        "value_kind": "bool",
        "insecure": False,
        "label": "Local password policy enforced",
        "description": "Whether the device's local password policy (length, complexity) is switched on at all.",
    },
    "IA.password_min_length": {
        "type": "scalar",
        "value_kind": "number",
        "worse": "lower",
        "label": "Minimum password length",
        "description": "Minimum number of characters the device's local password policy requires (0 = policy disabled).",
    },
    "IA.password_min_uppercase": {
        "type": "scalar",
        "value_kind": "number",
        "worse": "lower",
        "label": "Required uppercase characters",
        "description": "Minimum number of uppercase letters the local password policy requires.",
    },
    "IA.password_min_lowercase": {
        "type": "scalar",
        "value_kind": "number",
        "worse": "lower",
        "label": "Required lowercase characters",
        "description": "Minimum number of lowercase letters the local password policy requires.",
    },
    "IA.password_min_numeric": {
        "type": "scalar",
        "value_kind": "number",
        "worse": "lower",
        "label": "Required numeric characters",
        "description": "Minimum number of digits the local password policy requires.",
    },
    "IA.password_min_special": {
        "type": "scalar",
        "value_kind": "number",
        "worse": "lower",
        "label": "Required special characters",
        "description": "Minimum number of special (non-alphanumeric) characters the local password policy requires.",
    },
    "IA.password_min_changed_chars": {
        "type": "scalar",
        "value_kind": "number",
        "worse": "lower",
        "label": "Characters changed on password change",
        "description": "Minimum number of character positions that must differ when a password is changed.",
    },
    "IA.remote_auth_servers": {
        "type": "list",
        "label": "Central authentication servers",
        "description": "RADIUS / TACACS+ servers configured for administrator authentication.",
    },
    "SC.ssh_macs_fips_only": {
        "type": "scalar",
        "value_kind": "bool",
        "insecure": False,
        "label": "SSH MACs restricted to SHA-2",
        "description": "Whether the SSH server is explicitly restricted to FIPS-validated SHA-2 HMACs (no SHA-1 or MD5).",
    },
    "SC.ssh_ciphers_fips_only": {
        "type": "scalar",
        "value_kind": "bool",
        "insecure": False,
        "label": "SSH ciphers restricted to FIPS AES",
        "description": "Whether the SSH server is explicitly restricted to FIPS-approved AES ciphers (no 3DES, ChaCha20 or other non-approved cipher).",
    },
    # Added 2026-09-28 for more imported DISA STIG rules (rules/stig_catalog_map.yaml).
    "SC.icmp_redirects_all_disabled": {
        "type": "scalar", "value_kind": "bool", "insecure": False,
        "label": "ICMP redirects off on every interface",
        "description": "Whether every interface explicitly disables ICMP redirects (no ip redirects).",
    },
    "SC.icmp_unreachables_all_disabled": {
        "type": "scalar", "value_kind": "bool", "insecure": False,
        "label": "ICMP unreachables off on every interface",
        "description": "Whether every interface, including Null0, explicitly disables ICMP unreachable messages.",
    },
    "SC.proxy_arp_all_disabled": {
        "type": "scalar", "value_kind": "bool", "insecure": False,
        "label": "Proxy ARP off on every interface",
        "description": "Whether every (non-loopback) interface explicitly disables proxy ARP, so every external one does too.",
    },
    "SC.external_interface_lldp": {
        "type": "scalar", "value_kind": "bool", "insecure": True,
        "label": "LLDP on external interfaces",
        "description": "Whether LLDP may transmit on interfaces facing outside the organization's network.",
    },
    "SC.gratuitous_arp_enabled": {
        "type": "scalar", "value_kind": "bool", "insecure": True,
        "label": "Gratuitous ARP",
        "description": "Whether the device sends gratuitous ARPs (enabled and disabled globally on IOS).",
    },
    "SC.ip_directed_broadcast": {
        "type": "scalar", "value_kind": "bool", "insecure": True,
        "label": "IP directed broadcast",
        "description": "Whether any interface forwards IP directed broadcasts (a smurf-attack amplifier).",
    },
    "SC.cef_enabled": {
        "type": "scalar", "value_kind": "bool", "insecure": False,
        "label": "Cisco Express Forwarding",
        "description": "Whether CEF is enabled (resilience against high-rate traffic that would otherwise be process-switched).",
    },
    "SC.auto_config_features": {
        "type": "list",
        "label": "Auto-configuration / zero-touch features",
        "description": "Configuration auto-loading or zero-touch deployment features found (service config, boot network, CNS).",
    },
    "SC.nonsecure_services": {
        "type": "list",
        "label": "Unnecessary or nonsecure services",
        "description": "Legacy services found enabled (finger, small servers, bootp server, HTTP server, rcmd, ...).",
    },
    "SC.aux_port_exec_disabled": {
        "type": "scalar", "value_kind": "bool", "insecure": False,
        "label": "Auxiliary port disabled",
        "description": "Whether the auxiliary line explicitly disables EXEC (no exec).",
    },
    "SC.ipv6_site_local_used": {
        "type": "scalar", "value_kind": "bool", "insecure": True,
        "label": "IPv6 site-local addresses",
        "description": "Whether any deprecated IPv6 site-local (FEC0::/10) address is configured.",
    },
    "AU.log_timestamps": {
        "type": "scalar", "value_kind": "bool", "insecure": False,
        "label": "Date/time stamps on log records",
        "description": "Whether log records carry the date and time (not just uptime).",
    },
    "AU.login_failure_logging": {
        "type": "scalar", "value_kind": "bool", "insecure": False,
        "label": "Failed logons logged",
        "description": "Whether unsuccessful logon attempts generate audit records.",
    },
    "AU.login_success_logging": {
        "type": "scalar", "value_kind": "bool", "insecure": False,
        "label": "Successful logons logged",
        "description": "Whether successful logons generate audit records.",
    },
    "AU.logging_trap_level": {
        "type": "scalar", "value_kind": "number", "worse": "lower",
        "label": "Syslog severity sent to the log server",
        "description": "Most detailed syslog severity level sent to remote hosts (0 emergencies ... 7 debugging; -1 = off).",
    },
    "AC.mgmt_line_timeout_minutes": {
        "type": "scalar", "value_kind": "number", "worse": "higher_or_zero",
        "label": "Idle timeout on every management line",
        "description": "Longest idle timeout across the console and VTY lines (0 = never).",
    },
    "SC.http_mgmt_enabled": {
        "type": "scalar", "value_kind": "bool", "insecure": True,
        "label": "HTTP(S) management server",
        "description": "Whether the device's HTTP or HTTPS management server is enabled.",
    },
    "AC.http_idle_timeout_seconds": {
        "type": "scalar", "value_kind": "number", "worse": "higher_or_zero",
        "label": "HTTP management idle timeout",
        "description": "Idle timeout, in seconds, of HTTP(S) management sessions.",
    },
    "IA.ssh_root_login_denied": {
        "type": "scalar", "value_kind": "bool", "insecure": False,
        "label": "Root login over SSH denied",
        "description": "Whether SSH logon as root is denied outright.",
    },
    "SC.ssh_tcp_forwarding_disabled": {
        "type": "scalar", "value_kind": "bool", "insecure": False,
        "label": "SSH TCP forwarding disabled",
        "description": "Whether TCP port forwarding through the SSH server is disabled.",
    },
    "SC.web_management_enabled": {
        "type": "scalar", "value_kind": "bool", "insecure": True,
        "label": "Web management (J-Web) enabled",
        "description": "Whether a web-management service stanza is configured.",
    },
    "SC.ftp_enabled": {
        "type": "scalar", "value_kind": "bool", "insecure": True,
        "label": "FTP service",
        "description": "Whether the FTP management service is enabled.",
    },
    "CM.config_rollbacks": {
        "type": "scalar", "value_kind": "number", "worse": "lower",
        "label": "Stored configuration rollbacks",
        "description": "How many previous configurations the device keeps for rollback.",
    },
    "AU.timezone_utc": {
        "type": "scalar", "value_kind": "bool", "insecure": False,
        "label": "Time zone is UTC",
        "description": "Whether the device clock (and so log time stamps) is set to UTC/GMT.",
    },
    "AC.ssh_connection_limit": {
        "type": "scalar", "value_kind": "number", "worse": "higher_or_zero",
        "label": "Concurrent SSH session limit",
        "description": "Maximum number of simultaneous SSH management sessions.",
    },
    "AU.remote_syslog_changelog": {
        "type": "scalar", "value_kind": "bool", "insecure": False,
        "label": "Configuration changes sent to a log server",
        "description": "Whether an external syslog host receives change-log (or all) events at severity info or more detailed.",
    },
    "AU.remote_syslog_all_info": {
        "type": "scalar", "value_kind": "bool", "insecure": False,
        "label": "All events at info sent to a log server",
        "description": "Whether an external syslog host receives facility any at severity info or more detailed.",
    },
    "AU.remote_syslog_all_any": {
        "type": "scalar", "value_kind": "bool", "insecure": False,
        "label": "All events at every severity sent to a log server",
        "description": "Whether an external syslog host receives facility any, severity any.",
    },
    "AU.local_syslog_all_any": {
        "type": "scalar", "value_kind": "bool", "insecure": False,
        "label": "All events at every severity kept locally",
        "description": "Whether a local syslog file captures facility any, severity any.",
    },
    "SC.snmpv3_auth_sha2": {
        "type": "scalar", "value_kind": "bool", "insecure": False,
        "label": "Every SNMPv3 user authenticates with SHA-2",
        "description": "Whether every configured SNMPv3 user authenticates with SHA-256 or stronger.",
    },
    "SC.snmpv3_priv_aes": {
        "type": "scalar", "value_kind": "bool", "insecure": False,
        "label": "Every SNMPv3 user encrypts with AES",
        "description": "Whether every configured SNMPv3 user uses AES privacy (encryption).",
    },
    "AC.login_lockout_seconds": {
        "type": "scalar", "value_kind": "number", "worse": "lower",
        "label": "Account lockout duration",
        "description": "How long, in seconds, an account stays locked after too many failed logons.",
    },
    "SC.fips_mode_enabled": {
        "type": "scalar", "value_kind": "bool", "insecure": False,
        "label": "FIPS mode",
        "description": "Whether the device runs in FIPS-CC mode (FIPS-validated cryptography only).",
    },
    "IA.ldap_uses_ldaps": {
        "type": "scalar", "value_kind": "bool", "insecure": False,
        "label": "Every LDAP server uses LDAPS",
        "description": "Whether every configured LDAP authentication server connects over LDAPS.",
    },
    "AU.ntp_custom_servers": {
        "type": "scalar", "value_kind": "bool", "insecure": False,
        "label": "NTP uses the configured servers",
        "description": "Whether NTP synchronizes with the explicitly configured servers (FortiOS type custom), not a vendor default pool.",
    },
    "CM.os_min_version_met": {
        "type": "scalar", "value_kind": "bool", "insecure": False,
        "label": "OS release at or above the STIG minimum",
        "description": "Whether the configuration's software release is at least the STIG's minimum (Junos 12.1X46).",
    },
    "AU.ntp_sync_enabled": {
        "type": "scalar", "value_kind": "bool", "insecure": False,
        "label": "NTP synchronization enabled",
        "description": "Whether clock synchronization over NTP is switched on.",
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
