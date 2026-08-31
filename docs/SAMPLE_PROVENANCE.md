# Sample and Fixture Provenance

This registry explains provenance decisions for binary evidence and intentional example reports. The machine-enforced list of retained files is [`sample-provenance.json`](sample-provenance.json). A PCAP, PCAPNG, EVTX, disk image, memory dump, or similar evidence file must not be committed unless its creator/source, exact permission or license citation, `permitted` redistribution status, exact SHA-256, expected indicators, sanitization status, category, and `approved-retained` status are recorded there. Unknown or negative permission values are not acceptable for retained evidence.

## Retained evidence samples

None. Phase 5 removed every previously tracked PCAP and EVTX because repository history did not establish redistribution permission or a license. No generated report was retained because its underlying evidence provenance and sanitization status were not established.

## Removed evidence ledger

The SHA-256 values below were computed from the files at Phase 4 commit `64bacf5c6ca229e8c40bf94dceeafd8eace89d27` before removal. This ledger records what was removed; it does not grant permission to redistribute the files.

| Former path | SHA-256 | Source/creator | Redistribution permission/license | Expected indicators | Sanitization status | Decision |
| --- | --- | --- | --- | --- | --- | --- |
| `tools/pcap-profiler/samples/capture.pcap` | `c9de216e167fc4eca80dbb798657b98f8af507ad74f14f7154ce121ffca36cf1` | Not established | Not established | Not documented | Not established | Removed |
| `tools/pcap-profiler/samples/capture_4.pcap` | `7100993082af6f7caaccf742cbaff48bfa0dbf8b5f252c0211a895329ed9d575` | Not established | Not established | Not documented | Not established | Removed |
| `tools/pcap-profiler/samples/demo_small.pcap` | `986f4dfc7d890821b90589298f5fdcbdcead388460b1904519495b491ebc166c` | Not established | Not established | Not documented | Not established | Removed |
| `tools/pcap-profiler/samples/qi_local_SYNACK_curl_jsonip.pcap` | `b0b0b0367c1744b64bef7a71dba7f05e8d9af2487e3271750976754903b41bdf` | Not established | Not established | Not documented | Not established | Removed |
| `tools/winlog-triage/samples/4799_remote_local_groups_enumeration.evtx` | `c998491414379a4cd7b2f2d6025b7e4c1d1e13e8c31c623368d32b7acebcf93f` | Not established | Not established | Not documented | Not established | Removed |
| `tools/winlog-triage/samples/discovery_bloodhound.evtx` | `34f153b6384a6842fe4c635ec224f7551aef2c69b89267715413fd7d00690eb0` | Not established | Not established | Not documented | Not established | Removed |
| `tools/winlog-triage/samples/discovery_enum_shares_target_sysmon_3_18.evtx` | `c939a9aa65b2b262154571b6290234f559e2b22546ebfe5a57fb792f452f4198` | Not established | Not established | Not documented | Not established | Removed |

## Admission procedure

1. Put deterministic test-only inputs under `tests/fixtures/`; put portfolio demonstrations under `examples/samples/`.
2. Establish and record creator/source and explicit redistribution permission or license.
3. Sanitize the content and document exactly what was changed, or explicitly justify why sanitization is unnecessary.
4. Compute SHA-256 from the final committed bytes and list the indicators a test or reviewer should expect.
5. Add an `approved-retained` record to `sample-provenance.json` with `path`, `category`, `source_creator`, `redistribution_status` set to `permitted`, the exact permission/license citation in `redistribution_permission`, `sha256`, `expected_indicators`, `sanitization_status`, and `status`.
6. Add the evidence/report file, the JSON manifest, and this registry in the same reviewed commit. Evidence extensions are ignored by default, so adding one requires an intentional `git add -f`.
7. Never substitute a repository commit author or uploader for evidence creator, ownership, or redistribution permission.
