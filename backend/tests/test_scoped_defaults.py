"""Block-scoped vendor data found by the held-out run (samples/heldout/):
only VTY lines decide the idle timeout, a VTY line without `transport input`
accepts telnet on IOS 15, and a FortiOS export whose every allowaccess line
omits telnet has telnet off."""
from app import vendor_defaults

CISCO = """version 15.2
hostname r1
line con 0
 exec-timeout 0 0
line vty 0 4
 exec-timeout 5 0
 transport input ssh
line vty 5 15
 transport input ssh
"""


def _apply(vendor, text, fields=None, units=None):
    fields, prov = dict(fields or {}), {}
    vendor_defaults.apply(vendor, "high", text, fields, prov, units)
    return fields, prov


def test_console_timeout_does_not_decide_the_vty_rule():
    text = CISCO.replace("line vty 5 15\n transport input ssh\n", "")
    fields, prov = _apply("cisco_ios", text, {"AC.session_idle_timeout_minutes": 0})
    assert fields["AC.session_idle_timeout_minutes"] == 5
    assert prov["AC.session_idle_timeout_minutes"]["confidence_tier"] != "vendor_default"
    assert prov["AC.session_idle_timeout_minutes"]["source_unit"] == "line vty 0 4: exec-timeout 5 0"


def test_vty_block_without_timeout_is_at_the_default_and_cannot_hide():
    fields, prov = _apply("cisco_ios", CISCO, {"AC.session_idle_timeout_minutes": 5})
    assert fields["AC.session_idle_timeout_minutes"] == 10
    assert prov["AC.session_idle_timeout_minutes"]["confidence_tier"] == "vendor_default"  # FAIL-only
    assert prov["AC.session_idle_timeout_minutes"]["source_unit"].startswith("line vty 5 15")


def test_vty_without_transport_input_accepts_telnet_on_ios15_only():
    text = CISCO.replace("line vty 5 15\n transport input ssh\n", "line vty 5 15\n exec-timeout 5 0\n")
    fields, prov = _apply("cisco_ios", text, {"AC.telnet_enabled": False})
    assert fields["AC.telnet_enabled"] is True and prov["AC.telnet_enabled"]["confidence_tier"] == "vendor_default"
    fields, _ = _apply("cisco_ios", text.replace("version 15.2", "version 17.9"), {"AC.telnet_enabled": False})
    assert fields["AC.telnet_enabled"] is False


FORTI_UNITS = ["system interface edit port1 set allowaccess ping https ssh",
               "system interface edit port2 ipv6 set ip6-allowaccess ping https"]


def test_fortios_allowaccess_without_telnet_is_evidence_telnet_is_off():
    fields, prov = _apply("fortinet_fortios", "config system global\nend\n", units=FORTI_UNITS)
    assert fields["AC.telnet_enabled"] is False and prov["AC.telnet_enabled"]["confidence_tier"] == "tier1"


def test_fortios_one_telnet_interface_blocks_the_absence_fact():
    units = FORTI_UNITS + ["system interface edit port3 set allowaccess ping telnet"]
    fields, _ = _apply("fortinet_fortios", "config system global\nend\n", units=units)
    assert "AC.telnet_enabled" not in fields  # left to the seed entry that matches that line


def test_fragments_get_nothing():
    fields, prov = {}, {}
    vendor_defaults.apply("fortinet_fortios", "medium", "", fields, prov, FORTI_UNITS)
    assert fields == {}
