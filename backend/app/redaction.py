"""Redaction pass - regex-only for this build (architecture-document.md §7:
entropy-based fallback is deferred, disclosed as a residual risk in §10).

Runs BEFORE anything reaches an LLM call or a review-queue UI. Every secret
value is replaced with a typed placeholder, never just deleted, so downstream
code (and a human reviewer) can still see THAT something was there without
seeing WHAT it was.

Deliberately includes one known-gap demo hook (see `DEMO_UNCAUGHT_EXAMPLE`
below) - architecture-document.md §7 asks the demo to show a failure case,
not just the happy path.
"""
import re
from dataclasses import dataclass, field


@dataclass
class RedactionResult:
    text: str
    hits: list = field(default_factory=list)  # [{"type": ..., "count": ...}]


# Each rule: (type_name, compiled regex, optional case-insensitive set of
# captured values that should NOT be redacted for this rule even though they
# matched, which capture group holds the actual secret to redact (default 1
# - only ENABLE_SECRET_HASH differs, see below)).
# `\S+` (any non-whitespace) is the wrong boundary for a value-capturing
# group here: in XML/JSON-embedded values, the value is often immediately
# followed by a structural delimiter with NO separating whitespace (e.g.
# `password=CANARY_NUTPASS</upsd_users></config></nut>`, `secret="x"`).
# `\S+` greedily swallows those delimiters as part of the "secret," and
# replacing that whole match deletes real closing tags/quotes from the file -
# found via a real pfSense config where this silently destroyed three closing
# tags and produced a file that no longer parses as XML at all (0 units, no
# error surfaced). `[^\s<>"']+` stops at whitespace or any of the delimiter
# characters that matter across CLI/XML/JSON, so only the actual value is
# captured and structure around it survives untouched.
_VALUE = r"[^\s<>\"']+"
# Cisco-style "encryption type" digit that sits between a keyword and its
# secret (`key 7 <hex>`, `password 0 <plain>`, `secret 9 <hash>`). It's kept
# visible - it says HOW the secret is stored, which compliance rules need -
# and must never be mistaken for the secret itself: before this was
# optional-matched, `tacacs-server key 7 0822455D0A16` redacted the "7" and
# left the real key in place while still reporting a hit (found 2026-09-25
# while building the demo sample set).
_TYPE = r"(?:\d+[ \t]+)?"
# Horizontal whitespace only in multi-token rules: `\s` also matches
# newlines, which would let a rule start on one line and capture a token
# from the next.
_WS = r"[ \t]+"

_RULES = [
    ("TYPE7_PASSWORD", re.compile(r"\bpassword 7 ([0-9A-Fa-f]+)\b"), None, 1),
    # Was hardcoded to type "5" only - types 8 and 9 (the ones CIS-1.4.1
    # actually wants: PBKDF2/SHA-256 and scrypt respectively) matched
    # nothing and their hashes went completely unredacted to the LLM/review
    # queue. Broadened to any type digit; the digit itself stays visible
    # (it's what AC.privileged_password_type needs to read) while only the
    # hash (group 2) is redacted.
    ("ENABLE_SECRET_HASH", re.compile(r"\benable secret (\d+) (" + _VALUE + r")"), None, 2),
    # Local user accounts: `username X [privilege N] [role R] secret <type>
    # <hash>` (IOS type 5/8/9, EOS `secret 5` / `secret sha512`).
    ("USER_SECRET_HASH",
     re.compile(r"(?m)^[ \t]*(?:aaa root|username" + _WS + r"\S+[^\n]*?)" + _WS
                + r"secret" + _WS + r"(?:\d+|sha512|sha256)?[ \t]*(" + _VALUE + r")"),
     None, 1),
    # Plain or weakly-typed CLI passwords: `enable password X`, `username X
    # password 0 X`, a line's ` password X`, `ip ftp password 0 X`, BGP
    # `neighbor N password X`. Anchored to known command starts so free text
    # that merely contains the word (a banner, a description) isn't touched.
    # `password encryption aes` is an IOS-XE command, not a secret.
    ("CLI_PASSWORD",
     re.compile(r"(?m)^[ \t]*(?:(?:enable|username|ip|neighbor|ppp)\b[^\n]*?" + _WS + r")?password"
                + _WS + _TYPE + r"(" + _VALUE + r")"),
     {"encryption"}, 1),
    # "public"/"private" are the well-known CIS-flagged DEFAULT community
    # strings (CIS-1.5.2/1.5.3) - not real secrets, so there's nothing to
    # protect by hiding them, and doing so was actively breaking those two
    # checks: once redacted to a generic placeholder, the compliance check
    # can never again tell a default string apart from a real custom one.
    # Any other community string still gets redacted normally.
    ("SNMP_COMMUNITY", re.compile(r"\bsnmp-server community (" + _VALUE + r")"), {"public", "private"}, 1),
    # SNMPv3 users: `snmp-server user U G v3 auth sha AUTHPASS priv aes 128 PRIVPASS`.
    ("SNMPV3_SECRET",
     re.compile(r"(?m)^[ \t]*snmp-server user\b[^\n]*?\bauth" + _WS + r"\S+" + _WS + r"(" + _VALUE + r")"),
     None, 1),
    ("SNMPV3_SECRET",
     re.compile(r"(?m)^[ \t]*snmp-server user\b[^\n]*?\bpriv" + _WS + r"\S+" + _WS + r"(?:\d+" + _WS + r")?("
                + _VALUE + r")"),
     None, 1),
    # `pre-shared-key X`, `pre-shared-key local|remote X`,
    # `pre-shared-key address A [mask] key X` (IKEv2 keyrings), and the
    # IKEv1 `crypto isakmp key X address A`.
    ("PRE_SHARED_KEY",
     re.compile(r"\bpre-shared-key" + _WS + r"(?:(?:local|remote)" + _WS + r"|address[^\n]*?\bkey" + _WS + r")?"
                + _TYPE + r"(" + _VALUE + r")", re.IGNORECASE),
     None, 1),
    ("PRE_SHARED_KEY", re.compile(r"\bcrypto isakmp key" + _WS + _TYPE + r"(" + _VALUE + r")", re.IGNORECASE), None, 1),
    # `tacacs-server key [7] X`, `tacacs-server host H key [7] X`,
    # `radius-server host H auth-port N key X`, and IOS-XE block style
    # (`tacacs server NAME` / ` key 7 X` on its own indented line). The
    # block form refuses a bare number (` key 1` is a key-chain entry id).
    ("AAA_KEY",
     re.compile(r"\b(?:tacacs-server|radius-server)\b[^\n]*?\bkey" + _WS + _TYPE + r"(" + _VALUE + r")",
                re.IGNORECASE),
     None, 1),
    ("AAA_KEY", re.compile(r"(?m)^[ \t]+key" + _WS + _TYPE + r"(?!\d+[ \t]*$)(" + _VALUE + r")"), None, 1),
    # Routing-protocol authentication: key-chain `key-string`, OSPF
    # `message-digest-key N md5 X` / `authentication-key X`.
    # NTP orders it differently - `ntp authentication-key <id> <algo> <key>
    # [type]` - so the generic rule below would capture the algorithm name
    # and leave the key; it gets its own rule, and the generic one skips it.
    ("ROUTING_AUTH_KEY",
     # Both real orders: `... md5 <key> 7` and `... md5 7 <key>`. The type is
     # a single digit, so it can't swallow an all-digit key.
     re.compile(r"\bntp authentication-key" + _WS + r"\d+" + _WS + r"\S+" + _WS + r"(?:\d" + _WS + r")?("
                + _VALUE + r")"),
     None, 1),
    ("ROUTING_AUTH_KEY",
     re.compile(r"\b(?:key-string|(?<!ntp )authentication-key|message-digest-key" + _WS + r"\d+" + _WS + r"md5)"
                + _WS + _TYPE + r"(" + _VALUE + r")"),
     None, 1),
    # Generic fallback for "key/secret/password: value" (flattened JSON,
    # key=value text) - deliberately broad, applied late so specific rules
    # above take priority. The optional quotes matter: redaction runs on the
    # RAW file, where JSON reads `"password": "x"` - a quote sits between
    # the keyword and the colon, and without allowing it this rule never
    # matched real JSON at all.
    ("GENERIC_SECRET_FIELD",
     re.compile(r"\b[\w-]*?(?:secret|password|passwd|passkey|psk|shared_key)[\"']?\s*[:=]\s*[\"']?(" + _VALUE + r")",
                re.IGNORECASE),
     None, 1),
    # XML *elements* use a completely different separator than the rule
    # above assumes ("<password>x</password>", not "password=x" or
    # "password: x") - found live on a real pfSense config:
    # <ppps><ppp><password>CANARY_PPPOEPASS</password></ppp></ppps> matched
    # NOTHING above, even though "password" is exactly the keyword the rule
    # is supposed to catch, because the character after it is ">", not
    # ":"/"=". Same keyword vocabulary, same "don't try to catch every
    # possible tag name" scope (a tag like <passphrase> or <ipsecpsk> is
    # still a disclosed gap, same as before) - this only closes the
    # separator gap, not the keyword-coverage one.
    # Tag names may contain hyphens (`<pre-shared-key>`, `<sha512-hash>`,
    # both real pfSense tags that `\w*` stopped at). `*-hash` elements are
    # stored password hashes; `<hash-algorithm>` etc. are NOT (that's a
    # setting the cipher rules read), hence "-hash" only as a suffix.
    ("XML_ELEMENT_SECRET",
     re.compile(r"<([\w-]*(?:secret|password|passwd|passkey|passphrase|psk|shared[_-]key|auth_pass)[\w-]*"
                r"|[\w]+-hash)>([^<]+)</\1>", re.IGNORECASE),
     None, 2),
]

# A secret shape neither the regex rules above nor (in this build) an entropy
# check would catch: a vendor-proprietary obfuscated blob with no recognizable
# keyword next to it. Used deliberately in rehearsal (architecture-document.md
# §7/§11) to show the gap honestly rather than only the happy path.
DEMO_UNCAUGHT_EXAMPLE = "set system root-authentication encrypted-password \"$6$abcXYZ123$notReallyRedacted\""


def redact(text: str) -> RedactionResult:
    counts: dict[str, int] = {}
    for type_name, pattern, keep_values, value_group in _RULES:
        redacted_count = 0

        def _sub(m, type_name=type_name, keep_values=keep_values, value_group=value_group):
            nonlocal redacted_count
            secret = m.group(value_group)
            if keep_values and secret.lower() in keep_values:
                return m.group(0)  # matched, but a known-safe value - leave as-is
            if secret.startswith("[REDACTED:"):
                return m.group(0)  # an earlier, more specific rule already handled it
            redacted_count += 1
            # Square brackets, not angle brackets: this placeholder gets
            # inserted into whatever format the raw file is (CLI text, JSON
            # string values, or XML text content) - redaction runs before
            # fingerprinting even knows the format. A literal "<" here reads
            # as the start of a new element to an XML parser (found via a
            # real "unbound prefix" ParseError on a real pfSense config with
            # a redacted secret - the whole file silently produced 0 units,
            # no error surfaced). "[...]" has no special meaning in any of
            # the three formats this pipeline handles.
            placeholder = f"[REDACTED:{type_name}]"
            if len(secret) >= 2 and secret[0] == secret[-1] and secret[0] in ("'", '"'):
                # `\S+` greedily swallowed a surrounding quote pair too (an
                # XML/JSON-style quoted attribute value, e.g. secret="x") -
                # replacing the whole quoted token with an unquoted
                # placeholder breaks XML attribute syntax (found via the same
                # real pfSense config: secret="..." became secret=[REDACTED:
                # ...], invalid). Keep the same quote marks around it.
                placeholder = f"{secret[0]}{placeholder}{secret[0]}"
            # Replace only the captured span, not every occurrence of the
            # secret's text in the match - `str.replace` would also hit the
            # type digit when the secret happens to equal it.
            start, end = m.start(value_group) - m.start(0), m.end(value_group) - m.start(0)
            whole = m.group(0)
            return whole[:start] + placeholder + whole[end:]

        text = pattern.sub(_sub, text)
        if redacted_count:
            # Several rules can share one type (e.g. both AAA_KEY shapes) -
            # report one total per type.
            counts[type_name] = counts.get(type_name, 0) + redacted_count
    return RedactionResult(text=text, hits=[{"type": t, "count": c} for t, c in counts.items()])
