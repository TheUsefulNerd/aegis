# Held-out evaluation configs

These seven files were collected on **2026-09-27** from public, permissively licensed
repositories. **AEGIS had not been run on any of them when they were added**, and they
carry no labels yet. None of them is one of the files in `samples/sample_input_config_files/`
or one of that folder's original sources.

Each file is the upstream file byte for byte, with one exception: values that look like
real secrets (password hashes, FortiOS `ENC` blobs, Junos `$9$` / IOS keyring pre-shared
keys) have been replaced with `FAKE-REDACTED`. The keyword in front of each value is kept
(`secret 5`, `encrypted-password "..."`, `ENC`, `secret sha512`, `key`), so the
configured hash or encryption *type* is still visible. Nothing else was changed: no lines
were added, removed or reordered, and line endings are unchanged (LF). SNMP community
strings (`public`, `networktocode`, `secure`) were left as they are, because they are
obvious defaults or sample values. SSH *public* keys in file 03 were also left, because
they are not secrets.

| # | File | Vendor / format | Source (pinned to commit) | License | What it is | Lines | Changes |
|---|------|-----------------|---------------------------|---------|------------|-------|---------|
| 01 | `heldout_01_cisco_ios_lhr_border_02.cfg` | Cisco IOS 15.2, running-config | https://github.com/batfish/batfish/blob/403cb18715a9f6aa31ed89d2e390a3f5d4b78cf3/networks/hybrid-cloud-aws/configs/lhr-border-02.cfg | Apache-2.0 | Border router from Batfish's hybrid-cloud (AWS) example network: AAA, SSH, IPsec VPN to AWS, OSPF/BGP, ACLs, con/aux/vty lines | 282 | 3 values redacted: `username demo ... secret 5` hash; 2 `pre-shared-key ... key` values (AWS VPN PSKs) |
| 02 | `heldout_02_cisco_ios_as2border1.cfg` | Cisco IOS 15.2, running-config | https://github.com/batfish/batfish/blob/403cb18715a9f6aa31ed89d2e390a3f5d4b78cf3/networks/example/live/configs/as2border1.cfg | Apache-2.0 | Border router from Batfish's canonical 3-AS example network: NTP, AAA, interface ACLs, OSPF/BGP, route-maps, con/aux/vty lines | 198 | None |
| 03 | `heldout_03_junos_set_srx1.cfg` | Juniper Junos 15.1X49-D15.4 (SRX), `set` format | https://github.com/batfish/batfish/blob/403cb18715a9f6aa31ed89d2e390a3f5d4b78cf3/tests/parsing-tests/networks/srx-testbed/configs/junos-srx-1.cfg | Apache-2.0 | SRX firewall from Batfish's SRX testbed: local users, SSH and web management, syslog, IKE/IPsec, screens, zone policies, host-inbound services, BGP | 118 | 5 values redacted: 4 `encrypted-password` MD5-crypt hashes; 1 IKE `pre-shared-key ascii-text "$9$..."` (reversible obfuscation) |
| 04 | `heldout_04_junos_qfx5200.conf` | Juniper Junos (QFX5200; `version 20200609.165031.6_builder.r1115480`), hierarchical `{}` format | https://github.com/ckishimo/juniper_display_set/blob/e466e02bd0c44f763279e2f4e8214126c4b26bbc/tests/example3.conf | Apache-2.0 | Full `show configuration` of a lab QFX switch, used as a test input for a display-set converter: system services, login, syslog, SNMP, LLDP, VLANs | 268 | 2 values redacted: root and `admin` `encrypted-password` strings (marked `## SECRET-DATA` upstream) |
| 05 | `heldout_05_fortigate_fgvm.conf` | Fortinet FortiGate VM (FortiOS 5.x era), `config ... end` format | https://github.com/napalm-automation-community/napalm-fortios/blob/6407c0dfc26d2e227c64867382b33d03524aa608/test/unit/fortios/initial.conf | Apache-2.0 | Complete FortiGate-VM configuration used as the NAPALM FortiOS driver's initial test config: global settings, interfaces/allowaccess, admins, NTP, DNS, replacement messages, UTM profiles, firewall objects and policies, logging | 3514 | 5 values redacted: 2 admin `set password ENC ...`; 2 local-certificate `set password ENC ...`; 1 `user local` `set passwd ENC ...`. The upstream file has no trailing newline (kept that way). |
| 06 | `heldout_06_fortigate_fwf60d.conf` | Fortinet FortiWiFi 60D, FortiOS 5.00 build 271 (`#config-version=FWF60D-5.00-FW-build271-140124`), `config ... end` format | https://github.com/napalm-automation-community/napalm-fortios/blob/6407c0dfc26d2e227c64867382b33d03524aa608/test/unit/mocked_data/test_get_config/normal/show.txt | Apache-2.0 | Configuration backup of a FortiWiFi-60D (with the `#config-version` header), used as NAPALM `get_config` mock data: global settings incl. admintimeout, interfaces, admins, SNMP sysinfo, NTP, users, firewall policy, logging | 402 | 2 values redacted: 1 admin `set password ENC ...`; 1 `user local` `set passwd ENC ...`. No trailing newline upstream (kept). |
| 07 | `heldout_07_arista_eos_nyc_leaf_01.txt` | Arista EOS, running-config | https://github.com/networktocode/netutils/blob/09d6fbe452b392f49272e802f6e7593a1562a739/tests/unit/mock/config/compliance/section/arista_eos/eos_full_sent.txt | Apache-2.0 | Leaf-switch running config used as netutils compliance test data: remote logging, NTP, SNMP communities and host, AAA, local user, BGP, eAPI/gNMI management | 196 | 1 value redacted: `username ntc ... secret sha512` hash. The file starts with an empty line and has no trailing newline upstream (both kept). |

Raw download URLs have the form
`https://raw.githubusercontent.com/<owner>/<repo>/<commit>/<path>`, using the owner, repo,
commit and path from the table.

## Notes on provenance

- Files 01-03 come from the Batfish project. 01 and 02
  are the example networks that Batfish publishes for its tutorials. 03 is part of a
  3-device SRX testbed used in Batfish's parsing tests.
- 04 is a real device export (it has a `## Last commit: 2020-08-14 ... by root` header).
  It was published as a test fixture in `ckishimo/juniper_display_set`.
- 05 and 06 come from the NAPALM community FortiOS driver. 05 has no `#config-version`
  header, and its hostname `FGVM010000035136` is a FortiGate-VM serial-style name.
- 07 comes from Network to Code's `netutils` library.
- Vendor versions are listed only where the file itself states them.

## Not included

- **pfSense `config.xml`:** we found no non-default pfSense config under a clearly
  permissive license. We did not substitute anything.
- **Better FortiGate candidates we rejected:** the Azure `Azure-vpn-config-samples`
  FortiGate full configuration has no license file. `cgustave/fgtconfig` has no license.
  `acidjunk/fortigate-config-parser` and `ChoBon/Parse-fortigate-configuration-files` are
  GPL-3.0.
