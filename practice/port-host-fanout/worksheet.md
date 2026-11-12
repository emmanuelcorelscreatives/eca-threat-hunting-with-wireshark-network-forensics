# Worksheet — investigate two kinds of fan-out

Use the delivered verified synthetic practice.pcap, then repeat with your own authorized offline capture. Do not transfer synthetic answers to another capture.

Source file: ______  Observation point and visible directions: ______  UTC window and boundaries: ______  Known collection gaps or NAT mapping: ______  Unknown coverage: ______

**Hypothesis:** Does one initiating host contact several ports on one target, the same port on several targets, both, or neither within this window? First inspect attempts with `ip.src == 192.0.2.10 && tcp.flags.syn == 1 && tcp.flags.ack == 0`. SYN alone is insufficient. Replace the source, target and destination port for your own capture.

**Port fan-out:** Hold source and target fixed with `ip.src == 192.0.2.10 && ip.dst == 198.51.100.20 && tcp.flags.syn == 1 && tcp.flags.ack == 0`. Record each **distinct destination port**, its first UTC time and frame reference: ______. Record later attempts to the same tuple separately: ______.

**Host fan-out:** Hold source and destination port fixed with `ip.src == 192.0.2.10 && tcp.dstport == 8443 && tcp.flags.syn == 1 && tcp.flags.ack == 0`. Record each **distinct target address**, first UTC time and frame reference: ______. Record repeats: ______. Here 8443 belongs to the supplemental design; the lecture's 443 is only an example.

**Replies:** Broaden to `ip.addr == 192.0.2.10 && tcp`. For each attempt, record its source and destination **IP and port**, nearby reply time/frame, and any visible third ACK: ______. Which tuples have no visible reply? ______. Do not turn absence or SYN-ACK alone into a completed-handshake claim.

Inspect **Statistics > Conversations** for start, duration and direction; its conversation count is not a distinct-host or distinct-port count. In **Statistics > I/O Graphs**, use `ip.src == 192.0.2.10 && tcp.flags.syn == 1 && tcp.flags.ack == 0` on the graph row and a one-second packet-count interval against the wider window, then return to first attempts to compare clustered and later activity. Pace is not intent.

Finding — packet observations: ______. Pattern interpretation and confidence within this visibility: ______. Alternative management or network/collection explanation **as a hypothesis**: ______. Approval, process identity, and activity outside the capture remain: ______.

Ask the asset owner: *Which job, target addresses, ports and time were approved for this initiating asset?* Ask the capture owner: *Did this client-facing point collect both directions throughout the stated window, including the documented gap?* If NAT is present, request the specific mapping before naming targets. Next lesson: analyze failed and partial connections in more detail.