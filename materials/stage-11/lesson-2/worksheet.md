# Worksheet — attempts are not verdicts

Work from the supplied full synthetic PCAP first. File and SHA-256: ____; emulated point: ____; first/last packet UTC: ____; scenario end: ____; observed directions and deliberate gaps: ____. Do not call the scenario window measured coverage.

1. Filter initiating SYNs. Record frame, UTC time, initiator, destination, ports and raw sequence number. Separate repeated SYNs to the same peer/port/sequence from distinct peers or ports. Which frames could be retries of one attempt? What does a diagnostic retransmission label depend on?
2. Filter resets. Record source/destination, frame and response interval. Which reset answers an opening SYN, and which occurs after a visible SYN-ACK and ACK? Clear the filter to substantiate the difference.
3. Filter IPv4/IPv6 destination unreachable errors. For each present error record outer sender, protocol-specific type/code and the quoted attempted packet. Cite the original frame, quoted IP endpoints, ports and sequence. What fields are absent from the eight-byte TCP quotation? Explain why IPv6 has no fixture result.
4. Use the combined pivot from setup, then clear it. Record which returning SYN-ACKs and ACK it hid. For each A–F exchange cite packets observed, response direction and timing, working explanation, alternatives and confidence. SYN-ACK alone proves neither completion nor application success; even a complete handshake establishes no application success.
5. Explain why one silent exchange cannot prove a drop, blocking, scanning, an unavailable service, or authorization. Consider missing/asymmetric collection, late replies, rate-limited ICMP, routing faults, management software and deliberate reachability testing. Distinguish synthetic design omissions from causes you could infer in a real file.
6. Write a short conclusion separating observation from interpretation, listing filters and packet references, competing explanations, visibility limits and authorization as unknown. Identify one endpoint-process, service, network-device or approved-task record that would most change confidence. Request only the relevant record.

## Separate authorized-recording assignment

Use an existing authorized offline recording if available under your organization's rules. This supplied synthetic lab does not fulfill that learner-specific task. Record its real filename, hash, collection point/window, visible directions and gaps. Apply the same pivots, clear them, cite actual packets and distinguish absent packets from absent network events. Report no matching packets honestly; do not fabricate E/F or IPv6 results. Never import synthetic answers or identities into your real file. Record host ownership and approved work if available; otherwise authorization remains unknown. Submit a concise evidence note with limits and one next check. If no authorized recording is available, submit the synthetic exercise and mark the recording assignment pending access.

Next lesson covers ARP, DHCP and local discovery; the observation point still limits what can be concluded.
