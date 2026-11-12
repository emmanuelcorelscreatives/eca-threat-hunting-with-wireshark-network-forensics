# Worksheet

## 1. Capture conditions first
For each file record: synthetic or collected; observation point; visible direction; time window; collection filter; drop-count evidence; version and profile. Distinguish authored timestamps from measured coverage. Write unknown where evidence is unavailable. Can an unknown boundary be repaired by a display filter?

## 2. IPv4 pieces
Apply `ip.flags.mf == 1 || ip.frag_offset > 0`. Record each matching frame's source, destination, protocol, Identification, offset and MF. Group using all four identity fields, not timing or ID alone. Convert offset units to bytes. Which group has sufficient contiguous pieces? Which has only a first piece? Explain why neither establishes where loss occurred. Contrast IP datagram reassembly with application content assembled across TCP segments.

## 3. IPv6
Apply `ipv6.fraghdr.ident`. Record Identification, offset and More Fragments for every match. Which packets form a split datagram? Which contains an atomic Fragment header? Who fragments IPv6 packets: source or intermediate router?

## 4. Saved length
Apply `frame.cap_len < frame.len` to both files. Identify source frames and the missing byte counts. Explain the difference between bytes absent from a saved record and an absent fragment packet. Can any display preference recover either?

## 5. Preferences and checksum interpretation
Record before and after values for IP/IPv6 reassembly, TCP desegmentation, and IP/TCP/UDP checksum validation, including version/profile and exact settings changed. Use the setup comparison commands and Windows inspection steps in `native-validation.md`.

For richer frames 8–11 record raw sequence, TCP payload length, IP fragmentation evidence and validated checksum status. Compare byte ranges and lengths. What does the zero checksum placeholder mean in this authored simulation? Why is IPv4 UDP status 3 not a bad-checksum finding? Compare IPv6 UDP results. Explain how invalid checksums can affect reassembly when validation is enabled without asserting an untested display result.

What independent evidence would establish actual offload? Specify authorized observation points, comparable exchange, direction, timing, interface/offload configuration and correlation method. Do these synthetic files supply that evidence?

## 6. Revisit conversations
In `practice.pcap`, select a TCP packet and use Analyze → Follow → TCP Stream. Record available text and the applied stream filter, then clear it and inspect raw sequence/ACK values, timing and direction. Identify saved-byte gaps, not just readable text. Inspect Expert Information and treat it as investigative clues, not a verdict. Do not assume the synthetic aggregate/segments in the richer file are separate measured exchanges.

## 7. Explain collection limitations
Explain how a transport-header capture filter can exclude later fragments lacking that header, while a display filter merely hides saved packets. Discuss late capture, path visibility, filtering and possible collection loss. Does an absent drop count prove completeness?

For every richer frame and the eight baseline frames, submit a table of observed fields, supported interpretation, uncertainty and next evidence needed. Use your own file's frame numbers for future captures, never borrowed example numbers.

## 8. Safe own-capture homework
Separately from generated practice, analyze a small authorized capture of your own benign exchange, or request an approved existing file. Preserve the original and document capture scope/time/filter/snap length and available collector statistics. Repeat the fragment, length and preference checks; use Follow only if a relevant conversation exists. No matches means only no matching saved packets. Do not manufacture fragmentation, disable security controls, or change hardware offload to complete this task. If an authorized second observation beyond the sender is unavailable, report offload as plausible at most. Finish with observed facts, inference, uncertainty and the specific collection that would resolve it.

Inspect the TCP Retransmission annotations on richer frames 9–11 in native-04-tcp.png. Write frame 8's raw sequence range and each later segment's range. Explain why combining overlapping conceptual views within one TCP flow produces these annotations, and why this does not establish actual retransmission, network loss or hardware offload.
