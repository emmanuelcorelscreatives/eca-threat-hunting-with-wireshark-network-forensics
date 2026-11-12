# Worksheet — failures, retries, and bursts

Use only the four synthetic CSVs for this exercise. Their exchange descriptions and event excerpts are authored scenario metadata, not decoded frames. State two hypotheses: an outdated service credential after a password change, and unexplained login activity.

1. From the environment map and change records, record the approved source, account, services, change time, and configuration-update time. Why can an address alone not establish a host or its normal role?
2. Group exchange IDs by source, account, destination, service, and time. For each group list request type, any response and result. Separate Kerberos code 25 from code 24; LDAP BindResponse 49 from another operation returning 49; BindResponse 0 from proof of compromise; and NTLM-related traffic from a known validation outcome.
3. Compare K01’s modelled resend with K01, K02, and K03 as separate exchanges. What packet-level information would be needed to verify retransmission and connection counts? Why would a Conversations total or I/O Graph peak alone be insufficient?
4. Correlate candidate exchanges with events 4771 and 4776 by account, source information, code or status, and UTC time. Identify an exchange without a matching supplied event. Explain why a 4776 row cannot identify the destination and why WKS-LAB-07 cannot be assigned to a particular endpoint here.
5. Divide exchange IDs into: consistent with the recorded service change; requiring separate investigation; normal negotiation or non-bind result; and unresolved outcome. Overlap is allowed. Do not treat a change record as proof of cause.
6. Write a short finding with distinct **scenario observations**, **inferences**, **unsupported claims**, **confidence limits**, and **next actions**. Specify which identity-owner, service-owner, maintenance, address-mapping, or source-process records would discriminate the hypotheses. If using an independent authorized capture, identify its scope, filters, matching frames, alternatives, and missing replies separately; no such frames are supplied here.

The next lesson examines cleartext exposure in training traffic; this exercise does not assess that topic.