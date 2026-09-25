"""Remediation - KB-template lookup ONLY for this build.

LLM-drafted remediation is deliberately cut for the demo (architecture-
document.md §7): it's the highest-risk, most prompt-injection-exposed
component in the whole system, and rushing it under time pressure is a worse
look than not shipping it yet. If no template exists for a (vendor, rule_id)
pair, the honest answer is "no remediation available", not an improvised one.
"""
from dataclasses import dataclass
from typing import Optional

# (vendor, rule_id) -> fix command(s). Copied verbatim from each control's
# own "Remediation:" section in the real CIS Cisco IOS XE 17.x Benchmark
# v2.2.1 PDF (verified 2026-09-15), not reconstructed from memory. Starter
# set for the seeded demo rules; grows as the cybersecurity teammate authors
# more rule YAML.
TEMPLATES: dict[tuple[str, str], str] = {
    ("cisco_ios", "CIS-1.2.2"): "line vty 0 4\n transport input ssh",
    ("cisco_ios", "CIS-2.1.1.2"): "ip ssh version 2",
    ("cisco_ios", "CIS-1.4.2"): "service password-encryption",
    ("cisco_ios", "CIS-2.2.4"): "logging host {syslog_server}",
    # PDF's actual remediation for "Set 'logging enable'" goes through the
    # config-archive feature, not a bare top-level command - copied exactly
    # as written, not simplified.
    ("cisco_ios", "CIS-2.2.1"): (
        "archive\n"
        " log config\n"
        "  logging enable\n"
        "  end"
    ),
    # Not a CIS-numbered control (see cis_ios_xe_17.yaml's own comment on
    # CIS-SUPPLEMENT-ACL-TELNET) - but the fix itself is standard, correct
    # Cisco IOS ACL-ordering guidance regardless of the citation gap.
    ("cisco_ios", "CIS-SUPPLEMENT-ACL-TELNET"): (
        "access-list 101 deny tcp any any eq 23\n"
        "access-list 101 permit ip any any\n"
        "! ensure the deny line is ABOVE any broader permit line - order matters"
    ),
    ("cisco_ios", "CIS-1.4.1"): "enable secret 9 <strong-password>",
    ("cisco_ios", "CIS-1.2.8"): "line vty 0 4\n exec-timeout 10 0",
    ("cisco_ios", "CIS-1.5.2"): "no snmp-server community private",
    ("cisco_ios", "CIS-1.5.3"): "no snmp-server community public",
    ("cisco_ios", "CIS-1.3.2"): "banner login c\n<legal notice text>\nc",
    ("cisco_ios", "CIS-1.2.5"): "line vty 0 4\n access-class 10 in",

    # "Batch 2" (2026-09-15) - 4 more CIS Cisco IOS XE controls.
    ("cisco_ios", "CIS-2.3.1.1"): "ntp authenticate",
    ("cisco_ios", "CIS-3.1.1"): "no ip source-route",
    ("cisco_ios", "CIS-3.1.2"): "interface <interface>\n no ip proxy-arp",
    ("cisco_ios", "CIS-2.1.7"): "no service pad",

    # DISA STIG - Cisco IOS XE Router RTR V3R5. Copied from her doc's own
    # Remediation text; two of these (V-216645) are prose because the STIG
    # requirement itself is protocol-dependent (which routing protocol is in
    # use determines the exact CLI), not a single fixed command.
    ("cisco_ios", "STIG-V-216662"): (
        "ip access-list extended <ACL_NAME>\n"
        " permit <required_traffic>\n"
        " deny ip any any log-input\n"
        "interface <external-interface>\n"
        " ip access-group <ACL_NAME> in"
    ),
    ("cisco_ios", "STIG-V-216645"): (
        "Configure the applicable routing protocol with an authenticated key chain "
        "using an approved HMAC mechanism, such as HMAC-SHA256, and apply the key "
        "chain to the routing protocol."
    ),
    ("cisco_ios", "STIG-V-216650"): (
        "ip access-list extended <COPP_ACL>\n"
        "class-map match-all <CLASS_NAME>\n"
        "policy-map <CONTROL_PLANE_POLICY>\n"
        "control-plane\n"
        " service-policy input CONTROL_PLANE_POLICY"
    ),
    ("cisco_ios", "STIG-V-230045"): "interface <external-interface>\n ipv6 nd ra suppress\nend",
    ("cisco_ios", "STIG-V-216675"): "interface <external-interface>\n no cdp enable",

    # CIS pfSense Firewall Benchmark v1.1.0 - UI-navigation instructions, not
    # CLI commands, since that's how pfSense's own benchmark documents its
    # remediations (WebGUI-driven configuration, not a shell).
    ("pfsense", "CIS-PF-1.8"): "Configure the pfSense WebGUI protocol to HTTPS under System > Advanced > Admin Access.",
    ("pfsense", "CIS-PF-4.1.2"): "Edit the applicable firewall rule and replace 'Any' in the Source field with the required source address, network, alias, or other explicitly approved source.",
    ("pfsense", "CIS-PF-4.1.5"): "Edit applicable firewall rules and enable the Log option.",
    ("pfsense", "CIS-PF-6.1"): "Configure a remote syslog server under Status > System Logs > Settings.",
    ("pfsense", "CIS-PF-5.5.1"): "In VPN > OpenVPN, edit the applicable server configuration and configure only approved strong ciphers and hashing algorithms under Cryptographic Settings.",

    # SONiC - there is no CIS/STIG benchmark for SONiC, so only the
    # vendor-neutral NIST/ISO rules apply to it. Commands are the documented
    # `config` CLI from sonic-net/sonic-utilities doc/Command-Reference.md
    # (checked 2026-09-25 at commit 627858630348): `config syslog add
    # <server_address>`, `config acl update full [--table_name T] <file>`,
    # `config save -y` (without which a change doesn't survive a reboot).
    # Not tested against a live SONiC device.
    ("sonic", "NIST-AU-4-1"): "sudo config syslog add <syslog_server_ip>\nsudo config save -y",
    ("sonic", "NIST-AU-2"): (
        "# forward logs off-box so activity is retained centrally\n"
        "sudo config syslog add <syslog_server_ip>\nsudo config save -y"
    ),
    ("sonic", "ISO-A.8.15"): (
        "# forward logs off-box so activity is retained centrally\n"
        "sudo config syslog add <syslog_server_ip>\nsudo config save -y"
    ),
    ("sonic", "NIST-AC-4"): (
        "# In the ACL rules file, give the DROP rule for the unwanted traffic a HIGHER\n"
        "# PRIORITY than any broader FORWARD rule (higher priority is evaluated first), then:\n"
        "sudo config acl update full --table_name <ACL_TABLE> <acl_rules.json>\n"
        "sudo config save -y"
    ),
    ("sonic", "ISO-A.8.20"): (
        "# In the ACL rules file, give the DROP rule for the unwanted traffic a HIGHER\n"
        "# PRIORITY than any broader FORWARD rule (higher priority is evaluated first), then:\n"
        "sudo config acl update full --table_name <ACL_TABLE> <acl_rules.json>\n"
        "sudo config save -y"
    ),
}


@dataclass
class Remediation:
    text: str
    source: str  # "template" - the only value this build ever produces


def get_remediation(vendor: str, rule_id: str, template_ref: Optional[str] = None) -> Optional[Remediation]:
    """A rule's own id first, then its `remediation_template_ref` - several
    NIST/ISO rules deliberately point at the equivalent CIS control's fix
    (e.g. NIST-IA-7 -> CIS-2.1.1.2, "ip ssh version 2"). Before that
    fallback existed, a failed NIST rule on a Cisco device showed "no
    template available" although the exact fix was on file."""
    for key in (rule_id, template_ref):
        if key and (text := TEMPLATES.get((vendor, key))) is not None:
            return Remediation(text=text, source="template")
    return None
