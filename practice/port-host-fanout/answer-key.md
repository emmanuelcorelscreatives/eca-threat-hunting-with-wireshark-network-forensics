# Answer key — newly authored synthetic fixture

Actual decoded frames match the packet plan. With source 192.0.2.10 and target 198.51.100.20 fixed: ports 22, 80, 8443 first occur at frames 1, 4, 6 at 12:00:05, 06, 07 UTC on 2025-03-01: three distinct ports. Frame 5 repeats port 80.

With source fixed and destination port 8443: targets 198.51.100.20, .21, .22 first occur at frames 6, 8, 10 at 12:00:07, 08, 40 UTC: three targets. Frame 9 repeats .21. Seven SYN-without-ACK packets represent five distinct source/target/destination-port combinations.

SYN-ACKs are frames 2, 7, 11; third ACKs 3 and 12 complete the observed three-packet setup for the frame-1 and frame-10 tuples. Frame 7 has no following ACK. No reverse packets appear for port 80 or .21:8443. The fixture does not prove those hosts never answered elsewhere. One-second attempt graph bins relative to the first packet show one attempt in bin 0, two in bin 1, one in bin 2, two in bin 3 and one in bin 35; verify packet times rather than interpreting graph counts as unique targets.

Both fan-out patterns occur. The first relevant attempts cluster near 12:00:05–08, with a later target at 40. Synthetic context declares a one-minute window and a 20–25-second gap; the PCAP does not prove continuous coverage or a real collection gap. A management job or assessment is plausible, unconfirmed. Request the initiating asset owner's approved target, port and schedule record, and ask the capture owner about direction/coverage if absence matters. Process, ownership, intent, approval, vulnerabilities and outside-window activity remain unknown.
