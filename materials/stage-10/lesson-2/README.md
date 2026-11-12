# Investigate redirects and download chains

This Academy-designed synthetic HTTP exercise supplements Stage 10 Lesson 2. The saved lesson deliberately demonstrates an empty view because no case PCAP was supplied. This new `practice.pcap` is independent practice, never evidence from that unavailable incident. All bodies are harmless text. The builder writes bytes offline without sending packets or resolving names.

Start with setup.md, complete worksheet.md and redirect-chain-worksheet.csv, then consult answer-guide.md. DATA_DICTIONARY.md explains the fields. actual-http.csv contains real TShark 4.4.0 decoding of this newly built fixture. fixture-spec.json and build_capture.py reproduce the exact PCAP. execution-proof.json records actual Linux CLI validation. No Windows or native GUI execution is asserted by these logs.

The capture represents an authored link with client 192.0.2.10, eight complete synthetic TCP conversations and 88 Ethernet frames, from 2025-01-16 12:00:00 UTC through 12:00:07.200000 UTC. Addresses are documentation ranges and names use .test. Server addresses vary even for repeated host names; these authored associations are not DNS observations. No DNS, TLS, browser history, endpoint evidence, preceding navigation, or real collection coverage is present. There are no intentional missing TCP segments. Absence in this fixture describes only the supplied finite recording.

Hypothesis: visible HTTP exchanges link the first visible page through proposed destinations to a text response. The exercise also includes an unobserved advertised destination, a cache response, a range response and an explicitly synthetic benign updater comparison. Neither names nor multiple destinations establish maliciousness.
