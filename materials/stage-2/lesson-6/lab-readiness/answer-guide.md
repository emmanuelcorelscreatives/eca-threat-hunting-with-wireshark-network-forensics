# Checkable answer guide

## Shared reference: lab-reference.pcapng

The unchanged public source has SHA-256 `ff377b9bbe3c06df6ef68fe10b9beed6735421ae61b77330e59af574b0286e50`. Its supplied converted PCAPNG has SHA-256 `2ac1a118da3e9c38d469fa0d048de889158dddf120804b539a00035f74cce9a3`. There are six captured frames. The clear-filter IPv4 Endpoints count is two: 192.0.2.10 and 192.0.2.53. The measured UTC window is 2026-11-11 00:00:00.000000 through 00:01:00.020000, duration 60.020 seconds. Read exact fractional values from `reference-checks.json`; the native Properties first/last display rounds to whole seconds in this run.

The accepted display filter `frame.number == 999999` hides all six frames without removing them. Native Properties shows six captured packets and a dash in its Displayed packet cell, with zero displayed bytes; the packet list/status and CLI confirm no displayed frames. Clearing restores the six stored frames. Zero captured packets in another file cannot be restored this way. The converted file is 828 bytes by filesystem and capinfos. This native 4.4.0 Properties summary reports 795 bytes, while its SHA-256 matches the full file. Preserve this observed build-specific accounting difference; neither length is a packet count. The packet-length total is 524 bytes, a third measurement.

Date and Time of Day is the local absolute display format; the worked example records `TZ=UTC`. It changes presentation only. Do not change recorded timestamps to reconcile a clock mismatch. The numeric source/destination addresses are the stable endpoint references when network-address resolution is off. A display label does not establish that its lookup occurred in the capture. Here the actual DNS rows separately show portal.academy.test and updates.academy.test, query type A and answer 198.51.100.20. That answer is not a packet endpoint.

The Lab Baseline profile must actually be active, with clear display filter, explicit date/time format and network-address resolution off. Reselect it and reopen the reference; check saved settings again. Record the time zone and endpoint tab/filter scope separately in the checklist. Never infer a live interface, capture filter or test outcome from this offline reference.

## Independent practice.pcap

This different six-frame synthetic file has SHA-256 `bfd669e26d7bb1abd15b51f22f6e042807db047f8863f395ab0c5a07d5428a95`, 628 bytes, UTC window 2025-01-16 12:00:00.000000 through 12:00:02.050000. Its IPv4 packet endpoints are 192.0.2.10, 192.0.2.11 and 192.0.2.53, count three. Actual decoded DNS names, A query types and answer values are in `all-frames.stdout.txt`; do not transfer the shared reference's count/window to this file.

## Reasoning and uncertainty

Captured packets with none displayed indicate a view problem in this controlled exercise. A busy interface alone cannot prove visibility of an approved request. On-machine traffic may take another observation point. A capture filter acts before storage; a display filter cannot recover blocked packets. Live-list updates can delay visible rows until stopping. If the captured count stays zero after a bounded approved test, check the observation point, interface, capture filter, whether the request traversed that point, and permissions if indicated. Do not infer network silence or maliciousness. If your file fails its supplied checks, record the mismatch and next useful test and mark readiness inconclusive.
