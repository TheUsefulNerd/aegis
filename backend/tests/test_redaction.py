"""Redaction runs before anything reaches an LLM, a log, or the review queue.
The property that matters: the secret is GONE from the output - not just
that a hit was counted (B3 below counted a hit while leaving the key in
place)."""
import pytest

from app.redaction import DEMO_UNCAUGHT_EXAMPLE, redact


def _types(result):
    return {h["type"]: h["count"] for h in result.hits}


@pytest.mark.parametrize("line, secret, expected_type", [
    ("password 7 0822455D0A16", "0822455D0A16", "TYPE7_PASSWORD"),
    ("enable secret 9 $9$abcDEF$ghiJKL", "$9$abcDEF$ghiJKL", "ENABLE_SECRET_HASH"),
    ("enable secret 5 $1$salt$hash", "$1$salt$hash", "ENABLE_SECRET_HASH"),
    ("username netadmin privilege 15 secret 9 $9$FAKE$HASH", "$9$FAKE$HASH", "USER_SECRET_HASH"),
    ("username admin privilege 15 role network-admin secret sha512 $6$x$y", "$6$x$y", "USER_SECRET_HASH"),
    ("aaa root secret 5 $1$FAKEsalt$h/", "$1$FAKEsalt$h/", "USER_SECRET_HASH"),
    ("username cisco privilege 15 password 0 hunter2", "hunter2", "CLI_PASSWORD"),
    ("enable password hunter2", "hunter2", "CLI_PASSWORD"),
    (" password hunter2", "hunter2", "CLI_PASSWORD"),
    ("ip ftp password 0 FtpPass", "FtpPass", "CLI_PASSWORD"),
    (" neighbor 192.0.2.1 password BgpPass", "BgpPass", "CLI_PASSWORD"),
    ("snmp-server community S3cretRO RO", "S3cretRO", "SNMP_COMMUNITY"),
    ("pre-shared-key FakePsk01", "FakePsk01", "PRE_SHARED_KEY"),
    ("pre-shared-key local FakePsk02", "FakePsk02", "PRE_SHARED_KEY"),
    ("pre-shared-key address 192.0.2.1 key FakePsk03", "FakePsk03", "PRE_SHARED_KEY"),
    ("crypto isakmp key FakeIsakmp address 192.0.2.1", "FakeIsakmp", "PRE_SHARED_KEY"),
    ("radius-server key FakeRadius", "FakeRadius", "AAA_KEY"),
    ("tacacs-server host 192.0.2.10 key FakeTacacs", "FakeTacacs", "AAA_KEY"),
    ("  key-string FakeKeyString", "FakeKeyString", "ROUTING_AUTH_KEY"),
    (" ip ospf message-digest-key 1 md5 FakeOspfMd5", "FakeOspfMd5", "ROUTING_AUTH_KEY"),
    (" ip ospf authentication-key FakeOspf", "FakeOspf", "ROUTING_AUTH_KEY"),
    ("<password>FakeXml</password>", "FakeXml", "XML_ELEMENT_SECRET"),
    ("<radius_secret>FakeRad</radius_secret>", "FakeRad", "XML_ELEMENT_SECRET"),
    ("<pre-shared-key>FakeIpsec</pre-shared-key>", "FakeIpsec", "XML_ELEMENT_SECRET"),
    ("<sha512-hash>$6$FakeHash</sha512-hash>", "$6$FakeHash", "XML_ELEMENT_SECRET"),
    ("<auth_pass>FakeOvpn</auth_pass>", "FakeOvpn", "XML_ELEMENT_SECRET"),
    ("password=CANARY_NUTPASS", "CANARY_NUTPASS", "GENERIC_SECRET_FIELD"),
])
def test_secret_is_removed_and_typed(line, secret, expected_type):
    result = redact(line)
    assert secret not in result.text
    assert f"[REDACTED:{expected_type}]" in result.text
    assert _types(result).get(expected_type) == 1


@pytest.mark.parametrize("line, secret", [
    # B3: the type digit used to be redacted instead of the key.
    ("tacacs-server key 7 0822455D0A16", "0822455D0A16"),
    ("radius-server key 7 0822455D0A16", "0822455D0A16"),
    ("radius-server host 10.1.1.1 auth-port 1645 acct-port 1646 key 7 11AA22", "11AA22"),
    ("tacacs server ISE\n address ipv4 192.0.2.5\n key 7 0822455D0A16", "0822455D0A16"),
    ("  key-string 7 045802150C2E", "045802150C2E"),
    # NTP puts the key between the algorithm and a trailing type digit.
    ("ntp authentication-key 1 md5 030752180500 7", "030752180500"),
    ("ntp authentication-key 1 md5 7 030752180500", "030752180500"),
])
def test_type_digit_stays_visible_secret_goes(line, secret):
    result = redact(line)
    assert secret not in result.text
    assert "[REDACTED:" in result.text


def test_type_digit_is_preserved_for_compliance_rules():
    # AC.privileged_password_type needs the digit; only the hash goes.
    assert redact("enable secret 9 $9$x").text == "enable secret 9 [REDACTED:ENABLE_SECRET_HASH]"
    assert redact("tacacs-server key 7 ABCD").text == "tacacs-server key 7 [REDACTED:AAA_KEY]"


def test_json_secrets_are_caught_despite_quotes():
    # B4: redaction runs on raw JSON, where a quote sits between key and colon.
    raw = '{"TACPLUS": {"global": {"passkey": "FakePasskey"}}, "X": {"password": "FakeJsonPass"}}'
    result = redact(raw)
    assert "FakePasskey" not in result.text and "FakeJsonPass" not in result.text
    assert '"passkey": "[REDACTED:GENERIC_SECRET_FIELD]"' in result.text
    assert _types(result) == {"GENERIC_SECRET_FIELD": 2}


@pytest.mark.parametrize("line", [
    "service password-encryption",
    "password encryption aes",
    "security passwords min-length 8",
    "banner motd ^C Please change your password now ^C",
    "key chain OSPF\n key 1",
    "<hash-algorithm>sha256</hash-algorithm>",
    "snmp-server community public RO",
    "snmp-server community private RW",
])
def test_non_secrets_are_left_alone(line):
    result = redact(line)
    assert result.text == line
    assert result.hits == []


def test_default_community_strings_stay_visible_for_cis_checks():
    # CIS-1.5.2/1.5.3 need to see "public"/"private" to flag them.
    assert "public" in redact("snmp-server community public RO").text


def test_xml_structure_survives_redaction():
    raw = "<a><password>x</password><secret_access_key>y</secret_access_key><b>keep</b></a>"
    import xml.etree.ElementTree as ET
    ET.fromstring(redact(raw).text)  # must still parse


def test_value_adjacent_to_closing_tag_does_not_eat_structure():
    raw = "<nut><upsd_users>password=CANARY</upsd_users></nut>"
    assert redact(raw).text == "<nut><upsd_users>password=[REDACTED:GENERIC_SECRET_FIELD]</upsd_users></nut>"


def test_hits_for_one_type_are_merged():
    raw = "tacacs-server key 7 AAAA\ntacacs server X\n key 7 BBBB"
    assert _types(redact(raw)) == {"AAA_KEY": 2}


def test_already_redacted_values_are_not_redacted_twice():
    result = redact("username bob password 7 0822455D0A16")
    assert result.text == "username bob password 7 [REDACTED:TYPE7_PASSWORD]"
    assert _types(result) == {"TYPE7_PASSWORD": 1}


def test_disclosed_gap_is_still_a_gap():
    # Documented residual risk (architecture-document.md §10): a keyword-less
    # vendor blob. If this starts being caught, update the docs/demo too.
    assert redact(DEMO_UNCAUGHT_EXAMPLE).hits == []
