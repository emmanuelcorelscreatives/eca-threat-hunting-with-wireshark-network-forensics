# Case brief: DNS-ENCODED-SUPPLEMENT-01

This intentionally synthetic offline Ethernet fixture simulates a client-facing view between documentation addresses 192.0.2.10 and 192.0.2.53. No packets were transmitted or collected from a live network. The deterministic UTC window is 2025-01-16 12:00:00.000000–12:00:00.020000; the design’s one-second outer window appears in marker.json. This is separate from the saved classroom LAB/TEFC example and unavailable proposed capture.

Test this narrow hypothesis: the selected TXT response content, decoded with the reference-documented Base64 method, matches harmless UTF-8 `OK` (hex 4f4b). Transaction 21589 (hex 5455) queries marker.training.example.test TXT/IN from client port 53200 to resolver port 53; the response reverses that tuple and contains one TXT string. Match query and response rather than treating a queried name as the answer field.

A representation match does not establish encryption, tunneling, exfiltration, original author, authorization, user/process identity or purpose. A legitimate encoded DNS value, including certificate-validation material, is a competing explanation. This fixture cannot decide real operational intent. If that mattered in an authorized real case, request endpoint, application and resolver evidence from the same limited time window, with collection coverage and ownership established separately.
