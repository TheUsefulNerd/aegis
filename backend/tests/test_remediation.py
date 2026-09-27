from app.remediation import TEMPLATES, get_remediation


def test_direct_template():
    assert get_remediation("cisco_ios", "CIS-2.1.1.2").text == "configure terminal\nip ssh version 2\nend\nwrite memory"


def test_nist_rule_falls_back_to_its_cis_template_ref():
    # NIST-SC-8 YAML points at CIS-2.1.1.2 - the same fix.
    assert "ip ssh version 2" in get_remediation("cisco_ios", "NIST-SC-8", "CIS-2.1.1.2").text


def test_template_ref_never_crosses_vendors():
    # A Cisco command must never be offered for a pfSense device.
    assert get_remediation("pfsense", "NIST-SC-8", "CIS-2.1.1.2") is None


def test_no_template_is_none_not_improvised():
    assert get_remediation("cisco_ios", "NIST-SC-13", None) is None


def test_sonic_templates_use_documented_config_cli_and_persist():
    sonic = {k: v for k, v in TEMPLATES.items() if k[0] == "sonic"}
    assert sonic, "SONiC should have remediation templates"
    for text in sonic.values():
        assert "sudo config " in text
        assert text.rstrip().endswith("sudo config save -y")  # otherwise lost on reboot


def test_acl_fix_targets_the_failing_acl_before_its_permit():
    # The old fix appended the deny AFTER the permit-all (still dead code).
    text = get_remediation("cisco_ios", "CIS-SUPPLEMENT-ACL-TELNET", context={"acl": "101"}).text
    assert "ip access-list extended 101" in text and " 5 deny tcp any any eq telnet" in text
    assert "permit ip any any" not in text


def test_enable_secret_fix_is_valid_syntax():
    assert "enable algorithm-type scrypt secret" in get_remediation("cisco_ios", "CIS-1.4.1").text
