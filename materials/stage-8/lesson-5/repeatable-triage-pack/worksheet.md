# Repeatable triage worksheet

1. State a bounded hypothesis: does the synthetic client 192.0.2.10 contact 198.51.100.20 on TCP 8080 during 2025-04-01 00:00:00 through 00:00:04 UTC inclusive? Routine health monitoring is an ordinary alternative to a malicious explanation. Test the request/response relationship, not just a large endpoint count.

2. Create your own source log from paths-manifest.csv. For each source record source ID, exact original and working paths, original and work SHA-256, capture point, stated coverage, visible directions, clock basis and unknown offsets, gaps, packet count, first/last timestamps, ordering, snaplen and available interface metadata, access restrictions, OS, tool versions, GUI profile and name resolution. Use evidence/source-log.json as the worked example and capinfos outputs for observed metadata. Classic PCAP supplies no named collector-interface identity; do not invent one. Make a coverage matrix and retain source-specific limits beside findings.

3. In the GUI open each checked working copy with name resolution disabled and UTC time display. Apply this literal expression, then record it, the endpoint type and actual Statistics checkbox state in your filter register:

```text
ip.addr == 192.0.2.10 && tcp.port == 8080 && frame.time_epoch >= 1743465600 && frame.time_epoch <= 1743465604
```

For every source use the following shell block. The variable file is always an original; work is its byte-identical working copy. Repeat with id=point-b and id=point-c. The lowercase -r reads the file, capital -Y selects displayed packets. They are not capture filters.

```sh
id=point-a
file="inputs/originals/$id.pcap"
work="results/work/$id.pcap"
filter='ip.addr == 192.0.2.10 && tcp.port == 8080 && frame.time_epoch >= 1743465600 && frame.time_epoch <= 1743465604'
capinfos -H "$file"
capinfos "$file"
capinfos -H "$work"
tshark -r "$work" -Y "$filter" -T fields -e frame.number > "results/$id/selected-original-frames.txt"
tshark -q -r "$work" -z endpoints,ip > "results/$id/endpoints-ip-whole.txt"
tshark -q -r "$work" -z conv,ip > "results/$id/conversations-ip-whole.txt"
tshark -q -r "$work" -z "endpoints,ip,$filter" > "results/$id/endpoints-ip-filtered.txt"
tshark -r "$work" -Y "$filter" -w "results/$id/filtered.pcapng"
tshark -r "$work" -Y "$filter" -T fields -e frame.number | wc -l
capinfos "results/$id/filtered.pcapng"
tshark -r "$work" -Y "$filter" -T fields -E header=y -E separator=, -E quote=d -E occurrence=f -e frame.number -e frame.time_epoch -e frame.len -e ip.src -e ip.dst > "results/per-source/$id.csv"
```

Compare GUI original frame selections with the recorded TShark list. Open Statistics → Endpoints, select IPv4, and separately record whether Limit to display filter is checked. Compare the unchecked table with whole-file endpoints and the checked table with the explicit filtered -z output. Also inspect IPv4 Conversations on each source and compare whole-file CLI outputs with the unchecked limit. Record equivalent views; IPv4 Endpoints differs from TCP Conversations. If GUI and CLI disagree, inspect source hash, filter, profile, name resolution, selected tab, scope and derivative renumbering. Endpoint statistics do not automatically inherit -Y. IPv6 and transport-specific views require explicit documented changes if other traffic calls for them. This supplied fixture is IPv4 TCP.

Record selected-line count and derivative packet count separately. Here they agree; that is an observation for these runs, not a general promise. TShark display-filter writes can include dependencies in other captures. Never cite derivative frame numbers as originals. Keep the transcript and source hash with every output; do not add endpoint/conversation totals across overlapping files.

4. Inspect raw CSV headers, blanks and row counts. The first occurrence policy can hide repeated fields in richer packets; change and document it when necessary. Preserve raw CSV and timestamp strings. Frame length is the original frame length field in this untruncated fixture, not unique application data; epoch is a timestamp, not a formatted local clock. Add IPv6 fields if needed, rather than treating blank IPv4 cells as dropped packets.

Create results/source-log.json following evidence/source-log.json, using your own checked paths/hashes and observations. Then run:

```sh
python3 label_and_sort.py --manifest paths-manifest.csv --source-log results/source-log.json --csv-dir results/per-source --labeled-dir results/per-source-labeled --out results/timeline-review.csv
```

The tool retains each raw row's strings, prepends source_id and original_input_filename, refuses duplicate original-frame pairs, writes separate labeled files, sorts by Decimal epoch and refuses existing outputs. It does not synchronize clocks or deduplicate packets. Confirm 10 rows survive and each source/frame reference is unique. Keep raw CSVs unchanged. Preserve both rows when timestamps or payloads match until packet and collection evidence justifies any stronger relationship.

5. Open representative original frames point-a 4, point-b 3 and point-c 1 in Wireshark. Record source, original frame, UTC/epoch basis, direction, visible decoded GET fields and nearby packets. Compare the exported row with the original. These are corresponding authored events, not byte-identical duplicate packets: source-local IPv4 IDs differ. Record missing direction and earlier traffic limits. Inspect point-a 5 for the response and raw ACK, plus the incomplete second exchange at point-a 6–7.

6. Package your manifest, coverage matrix, exact filter register, source log, commands/transcript, separately named whole-file summaries, filtered derivatives, raw and labeled CSVs, sorted timeline, original-frame checks and interpretation. Record transformations and authorized access restrictions. Ask a second analyst to verify original hashes, repeat commands into a different fresh directory, compare equivalent outputs and locate cited originals. Record actual differences and unresolved observations rather than forcing matching presentation. The shipped evidence is a worked author execution; it is not proof that your second analyst has completed this step.
