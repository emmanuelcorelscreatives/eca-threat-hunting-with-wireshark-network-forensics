# Checked answers for the supplied synthetic capture

These are observed TShark 4.4.0 selections, not incident findings. File: `practice.pcap`, SHA-256 9968bbde733cef6879415e2e0ec1ddb8545aa450e816a9e652dd1fc2fd46d107, seven frames. Synthetic case P01 maps to frame 1, through P07 to frame 7; the mapping was checked against decoded Ethernet, IP, raw TCP sequence/ack and ARP fields.

| Exact expression | Visible frames | Displayed / total |
|---|---|---|
| `ip.src == 192.0.2.10` | 1, 3 | 2 / 7 |
| `ip.addr == 192.0.2.10` | 1, 2, 3, 4 | 4 / 7 |
| `tcp && ip.addr == 192.0.2.10` | 1, 2 | 2 / 7 |
| `ip.src!= 192.0.2.10` | 2, 4, 5, 6 | 4 / 7 |
| `not (ip.src == 192.0.2.10)` | 2, 4, 5, 6, 7 | 5 / 7 |

Entry 1: frames 1 and 3 originate at the host; replies 2 and 4 are hidden by the source-only candidate. That candidate fails the both-direction intent. `ip.addr` preserves both directions and excludes unrelated IPv4 frames 5 and 6. Frame 7 is ARP and has no IPv4 field.

Entry 2: TCP frames 1 and 2 remain, UDP/DNS 3 and 4 and unrelated TCP 5 do not. This validates the narrower TCP selection within this file, not the all-protocol intent.

Entry 3: both negatives exclude host-source frames 1 and 3, but keep replies 2 and 4. Only negated equality retains ARP frame 7. Neither expression removes all host-involving traffic. This tests field existence, not just opposite strings.

An approved application could legitimately contact the host and match these filters. Check asset/application context before interpreting a match. No matching packet proves maliciousness or authorization. Clearing yields all seven frames; reapplying the host filter yields four. These authored timestamps and a virtual Ethernet link do not establish real coverage. A separate authorized working capture requires fresh observations and controls. Missing examples make its relevant checks inconclusive.
