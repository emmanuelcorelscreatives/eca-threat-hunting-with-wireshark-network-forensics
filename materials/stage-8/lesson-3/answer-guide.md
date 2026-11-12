# Checked answer guide

These are actual Linux TShark observations of the supplied synthetic files, not historical incident findings. Logs and `execution-receipt.json` give exact commands. Each source has 15 decoded frames; malformed-frame selections were empty with exit code zero. IP/TCP/UDP checksum status fields are in the actual field logs; do not infer endpoint offload behavior from this authored fixture.

For A, B and C, each unfiltered source has five IPv4 endpoints, one TCP conversation (11 captured frames), and two UDP conversations. A/B TCP totals are 601 captured frame bytes: client → peer is 6 frames/328 bytes and peer → client is 5/273. C TCP totals are 603 captured frame bytes: client → peer is 6/329 and peer → client is 5/274. DNS client → resolver is 1 frame/77 bytes and resolver → client is 1/93: two frames/170 bytes. The other UDP relationship is two frames/99 bytes: 1/52 and 1/47. Do not add endpoint byte totals to get unique traffic, because each packet contributes to both its endpoints.

In each source `ip.addr==192.0.2.10` selects 13 frames. Explicitly scoped statistics show three endpoints, the same one TCP relationship and one UDP DNS relationship. The unfiltered and `-Y`-alone statistics remain broad: `-Y` alone does not scope these `-z` tables. Actual `summary-X`, `scoped-X` and `Y-alone-X` outputs demonstrate the distinction. GUI verification must match file, profile, protocol tab, expression and visible “Limit to display filter” state. Read the exact native evidence index for visible findings; hidden fields are not asserted.

The common endpoint addresses are client 192.0.2.10, peer 198.51.100.20 and resolver 192.0.2.53. In A/B the client is 13 frames/771 bytes (Tx7/405, Rx6/366), peer is 11/601 (Tx5/273, Rx6/328). In C the client is 13/773 (Tx7/406, Rx6/367), peer is 11/603 (Tx5/274, Rx6/329). The resolver is 2/170 (Tx1/93, Rx1/77) in each source. The extra UDP addresses vary by file; use the exact per-file table below. Conversation arrows are relative to the displayed Address A/B ordering, not a guarantee that A is a real-world client.

## Source A — actual unfiltered output

```text
================================================================================
UDP Conversations
Filter:<No Filter>
                                                           |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
192.0.2.10:53200           <-> 192.0.2.53:53                    1 93 bytes        1 77 bytes        2 170 bytes     0.000000000         0.0200
192.0.2.77:55001           <-> 198.51.100.77:43000              1 47 bytes        1 52 bytes        2 99 bytes      0.500000000         0.0200
================================================================================
================================================================================
TCP Conversations
Filter:<No Filter>
                                                           |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
192.0.2.10:54000           <-> 198.51.100.20:40000              5 273 bytes       6 328 bytes      11 601 bytes     0.200000000         0.2000
================================================================================
================================================================================
IPv4 Endpoints
Filter:<No Filter>
                       |  Packets  | |  Bytes  | | Tx Packets | | Tx Bytes | | Rx Packets | | Rx Bytes |
192.0.2.10                    13           771          7             405           6             366   
198.51.100.20                 11           601          5             273           6             328   
192.0.2.53                     2           170          1              93           1              77   
192.0.2.77                     2            99          1              52           1              47   
198.51.100.77                  2            99          1              47           1              52   
================================================================================
```

## Source B — actual unfiltered output

```text
================================================================================
UDP Conversations
Filter:<No Filter>
                                                           |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
192.0.2.10:53200           <-> 192.0.2.53:53                    1 93 bytes        1 77 bytes        2 170 bytes     0.000000000         0.0200
192.0.2.88:55002           <-> 198.51.100.88:43000              1 47 bytes        1 52 bytes        2 99 bytes      0.500000000         0.0200
================================================================================
================================================================================
TCP Conversations
Filter:<No Filter>
                                                           |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
192.0.2.10:54000           <-> 198.51.100.20:40000              5 273 bytes       6 328 bytes      11 601 bytes     0.200000000         0.2000
================================================================================
================================================================================
IPv4 Endpoints
Filter:<No Filter>
                       |  Packets  | |  Bytes  | | Tx Packets | | Tx Bytes | | Rx Packets | | Rx Bytes |
192.0.2.10                    13           771          7             405           6             366   
198.51.100.20                 11           601          5             273           6             328   
192.0.2.53                     2           170          1              93           1              77   
192.0.2.88                     2            99          1              52           1              47   
198.51.100.88                  2            99          1              47           1              52   
================================================================================
```

## Source C — actual unfiltered output

```text
================================================================================
UDP Conversations
Filter:<No Filter>
                                                           |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
192.0.2.10:53201           <-> 192.0.2.53:53                    1 93 bytes        1 77 bytes        2 170 bytes     0.000000000         0.0200
192.0.2.77:55001           <-> 198.51.100.77:43000              1 47 bytes        1 52 bytes        2 99 bytes      0.500000000         0.0200
================================================================================
================================================================================
TCP Conversations
Filter:<No Filter>
                                                           |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
192.0.2.10:54001           <-> 198.51.100.20:40000              5 274 bytes       6 329 bytes      11 603 bytes     0.200000000         0.2000
================================================================================
================================================================================
IPv4 Endpoints
Filter:<No Filter>
                       |  Packets  | |  Bytes  | | Tx Packets | | Tx Bytes | | Rx Packets | | Rx Bytes |
192.0.2.10                    13           773          7             406           6             367   
198.51.100.20                 11           603          5             274           6             329   
192.0.2.53                     2           170          1              93           1              77   
192.0.2.77                     2            99          1              52           1              47   
198.51.100.77                  2            99          1              47           1              52   
================================================================================
```

## Packet-level comparison and interpretation

A and B repeat DNS/TCP fields and the same TCP four-tuple/sequence progression, with designed timestamps 50 ms apart. Their different declared observation points and overlapping windows are scenario metadata. Matching summaries and packet fields support a repeated-observation hypothesis but do not prove one real network event was captured twice. C is later and uses another client port and sequence space; compare the actual field logs and source specs, not just matching addresses. Raw sequence values differ from relative display numbers. Frame 6 carries a four-byte LAB newline payload in A/B and a five-byte LAB2 newline payload in C; packet/frame bytes include headers and are not application-data totals.

Per-file relative starts and durations use that file's capture origin; do not read them as absolute timestamps. DNS starts at relative zero; TCP starts at 0.2 seconds and lasts 0.2 seconds; the other UDP relationship starts at 0.5 seconds and lasts 0.02 seconds. Use frame.time_epoch for actual timestamp comparisons. Treat the author-declared collection windows separately from packet time bounds.

A strong answer keeps all three sources and each filter scope separate. High counts can be ordinary authorized work; a missing scoped row means no observation under that scope. Endpoint IPs do not identify people/processes or malicious intent. A useful next check compares representative packets, TCP tuples, timestamps and sequence progression together with collection design. If CLI/GUI disagree, check hashes, profile, protocol layer and filter-limit state first, then retain any unresolved mismatch as inconclusive. No network-wide absence follows from these files.
