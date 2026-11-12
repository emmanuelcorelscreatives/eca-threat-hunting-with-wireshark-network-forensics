# Data dictionary

## Files and provenance
- `practice.pcap`: unchanged 583-byte synthetic baseline; rebuilt bytes match SHA-256 `171c62e1bc91dfad4735175f4706a8ab715bb6d5d054bc950e41f5545c7711a4`.
- `fixture-spec.json`: eight authored events, documentation IPv4 addresses, raw TCP sequence/ACK values, text payloads and intentional saved-length limit. `offline-builder.py` writes the baseline without networking.
- `lesson-6-cases.pcapng`: eleven richer synthetic Ethernet records, 7112 bytes; SHA-256 `3d4b9610390ff17b52b114eb9412718adf74c7f27695fc1bb7f4d6d7ceecff8e`.
- `generate_cases.py`: deterministic stdlib builder/verifier; no network access; refuses existing output capture or manifest.
- `case-manifest.csv`: frame/case/role, captured and reported lengths, explanatory notes, authored observation-point/direction/window/filter/drop metadata. These are simulation labels, not measured collection evidence.
- `decoded-fields.stdout.txt`: actual Linux TShark field decode. Empty cells are absent field values in that run.
- `execution-proof.json` and associated stdout/stderr: supplied execution records, not Windows GUI evidence.

## Fields
|Field|Meaning and limitation|
|---|---|
|`frame.number`|Index within this file; not portable to another capture|
|`frame.cap_len` / `frame.len`|Saved bytes / reported original frame bytes; inequality identifies shortened records|
|`ip.src`, `ip.dst`, `ip.proto`, `ip.id`|IPv4 fragment grouping tuple; ID alone is insufficient|
|`ip.frag_offset`|Offset in eight-byte units, not bytes|
|`ip.flags.mf`|More Fragments flag; clear on final fragment but also on unfragmented packets|
|`ipv6.fraghdr.ident`|Fragment Identification; group with addresses and relevant protocol context|
|`ipv6.fraghdr.offset`, `ipv6.fraghdr.more`|Eight-byte offset units and more flag; zero/false may be atomic|
|`tcp.seq_raw`, `tcp.ack_raw`|Unadjusted sequence/acknowledgment values; SYN consumes sequence space|
|`tcp.len`|TCP payload length, not Ethernet frame size|
|`tcp.checksum.status`|Here 0 BAD for synthetic zero placeholder, 1 GOOD for computed post-simulation checksums; neither proves actual offload|
|`udp.checksum.status`|Here 3 means absent IPv4 UDP checksum, not BAD; 1 means GOOD for the IPv6 examples|
|`ip.reassembled_in`, `ipv6.reassembled.in`|Optional analysis references; blank in all supplied richer rows|

A capture filter controls what is saved. A display filter controls which saved records are shown. IP reassembly builds a datagram from fragments; TCP desegmentation supports higher-layer content across TCP segments. Neither operation creates evidence absent from the file.
