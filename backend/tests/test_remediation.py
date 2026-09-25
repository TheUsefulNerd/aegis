from app.remediation import TEMPLATES, get_remediation


def test_direct_template():
    assert get_remediation("cisco_ios", "CIS-2.1.1.2").text == "ip ssh version 2"


def test_nist_rule_falls_back_to_its_cis_template_ref():
    # NIST-IA-7's YAML points at CIS-2.1.1.2 - the same fix.
    assert get_remediation("cisco_ios", "NIST-IA-7", "CIS-2.1.1.2").text == "ip ssh version 2"


def test_template_ref_never_crosses_vendors():
    # A Cisco command must never be offered for a pfSense device.
    assert get_remediation("pfsense", "NIST-IA-7", "CIS-2.1.1.2") is None


def test_no_template_is_none_not_improvised():
    assert get_remediation("cisco_ios", "NIST-SC-13", None) is None


def test_sonic_templates_use_documented_config_cli_and_persist():
    sonic = {k: v for k, v in TEMPLATES.items() if k[0] == "sonic"}
    assert sonic, "SONiC should have remediation templates"
    for text in sonic.values():
        assert "sudo config " in text
        assert text.rstrip().endswith("sudo config save -y")  # otherwise lost on reboot
