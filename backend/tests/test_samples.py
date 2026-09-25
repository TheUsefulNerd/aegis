"""Regression fixtures: every shipped sample must fingerprint as documented,
survive redaction structurally, and never leave a planted fake secret in the
text that reaches the classifier."""
import re

import pytest

from app import fingerprint, redaction, units
from conftest import read_sample

DEMO = "sample_input_config_files"

# (file parts, vendor, unit count, redaction types that must fire)
CASES = [
    (("cisco_ios_sample.txt",), "cisco_ios", 12, {"ENABLE_SECRET_HASH", "SNMP_COMMUNITY"}),
    (("pfsense_config_sample.xml",), "pfsense", 7, set()),
    (("sonic_config_db_sample.json",), "sonic", 7, set()),
    ((DEMO, "01_cisco_ios_branch_router_hardened.txt"), "cisco_ios", 81,
     {"ENABLE_SECRET_HASH", "USER_SECRET_HASH", "TYPE7_PASSWORD", "SNMP_COMMUNITY", "PRE_SHARED_KEY", "AAA_KEY"}),
    ((DEMO, "02_pfsense_hq_firewall.xml"), "pfsense", 57, {"XML_ELEMENT_SECRET", "GENERIC_SECRET_FIELD"}),
    ((DEMO, "03_sonic_spine_linecard_config_db.json"), "sonic", 70, set()),
    ((DEMO, "04_cisco_csr1000v_edge_misconfigured.txt"), "cisco_ios", 55, {"CLI_PASSWORD"}),
    ((DEMO, "05_arista_veos_unseen_vendor.txt"), "unknown", 18, {"USER_SECRET_HASH"}),
    ((DEMO, "06_cisco_csr1000v_edge_remediated.txt"), "cisco_ios", 64,
     {"ENABLE_SECRET_HASH", "USER_SECRET_HASH", "SNMP_COMMUNITY"}),
]


@pytest.mark.parametrize("parts, vendor, unit_count, types", CASES)
def test_sample_pipeline_front_half(parts, vendor, unit_count, types):
    redacted = redaction.redact(read_sample(*parts))
    fp = fingerprint.fingerprint(redacted.text)
    unit_list = units.split_into_units(redacted.text, fp["format"])

    assert fp["vendor"] == vendor
    # Unit count unchanged by redaction = no structure was damaged (an XML
    # file that stops parsing silently yields 0 units).
    assert len(unit_list) == unit_count
    assert types <= {h["type"] for h in redacted.hits}
    # Every fake secret planted in the demo set contains "FAKE" - none may
    # survive into what the classifier sees.
    leaked = [u for u in unit_list if re.search(r"FAKE", u) and "[REDACTED:" not in u]
    assert leaked == []


def test_demo_set_covers_every_redaction_type():
    seen = set()
    for parts, *_ in CASES:
        seen |= {h["type"] for h in redaction.redact(read_sample(*parts)).hits}
    expected = {"TYPE7_PASSWORD", "ENABLE_SECRET_HASH", "USER_SECRET_HASH", "CLI_PASSWORD", "SNMP_COMMUNITY",
                "PRE_SHARED_KEY", "AAA_KEY", "GENERIC_SECRET_FIELD", "XML_ELEMENT_SECRET"}
    assert expected <= seen


def test_novel_teach_once_line_is_in_the_demo_files():
    line = "orgpolicy-tag SEC-BASELINE-77 apply"
    for name in ("01_cisco_ios_branch_router_hardened.txt", "04_cisco_csr1000v_edge_misconfigured.txt"):
        assert line in read_sample(DEMO, name).splitlines()


def test_fingerprint_does_not_call_every_xml_pfsense():
    fp = fingerprint.fingerprint('<?xml version="1.0"?><configuration><system/></configuration>')
    assert fp["vendor"] == "unknown_xml"


def test_pfsense_filter_rules_are_reassembled_in_order():
    # One ACL-syntax line per rule, so "block telnet" is never classified
    # from its `destination.port=23` field alone (architecture §3.5).
    xml = """<?xml version="1.0"?><pfsense><filter>
      <rule><type>block</type><protocol>tcp</protocol><interface>wan</interface><descr>no telnet</descr>
            <source><any/></source><destination><network>wanip</network><port>23</port></destination><log/></rule>
      <rule><type>pass</type><interface>lan</interface><source><network>lan</network></source><destination><any/></destination></rule>
      <rule><type>pass</type><disabled/><source><any/></source><destination><any/></destination></rule>
      <rule><type>pass</type><protocol>tcp</protocol><source><address>192.0.2.9</address></source>
            <destination><any/><port>1000:2000</port></destination></rule>
    </filter></pfsense>"""
    assert units.split_into_units(xml, "xml") == [
        "pfsense.filter.rule[0].descr=no telnet",
        "access-list pfsense-wan deny tcp any wanip eq 23 log",
        "access-list pfsense-lan permit ip lan any",
        "access-list pfsense-any permit tcp 192.0.2.9 any range 1000 2000",
    ]


def test_reassembled_pfsense_rules_evaluate_first_match():
    from app.rule_engine import FAIL, PASS, evaluate
    telnet = {"field": "AC.acl_rules", "match": {"protocol": "tcp", "port": 23}, "want_action_if_matched": "deny"}
    acl = ["access-list pfsense-wan deny tcp any wanip eq 23", "access-list pfsense-lan permit ip lan any"]
    assert evaluate("ordered-first-match", telnet, {"AC.acl_rules": acl}).result == PASS
    assert evaluate("ordered-first-match", telnet, {"AC.acl_rules": acl[::-1]}).result == FAIL
