# Student worksheet

Keep packet facts, scenario assumptions and real-case unknowns in separate columns. Submit a completed timeline, three scenario conclusions and a concise evidence request.

1. Record capture SHA256, first and last UTC packet times, count, authored observation point and unknown collection continuity. What does the long interval without authored packets fail to prove?
2. List the three DNS response frames, querying endpoints, resolver, names and answers. Which answer has no shown connection? Why does a matching answer followed by a TCP start fail to identify the process that used the name?
3. Record four initial SYN frames with exact local/remote sockets. Which starts belong to the same candidate host but different local ports? Compare candidate and other-host start intervals. Why is similar recurrence insufficient to transfer approval?
4. Record ClientHello/ServerHello frames and visible names. Is a TLS handshake completed? Is any application message supplied? Challenge “the encrypted session carried commands” using only supplied evidence.
5. Clear the display filter, open TCP Conversations and state the filter-limit checkbox state. Record observed starts, durations, direction and six-packet counts for each pair. Then apply the SYN filter with the limit enabled and explain why the table describes a different observation subset. Clear the filter afterwards.
6. Fill: `UTC | endpoint and socket | DNS observation | transport/TLS observation | application available/unavailable | source frame/card | coverage limit`.
7. Review approved, conflicting and unavailable scenarios independently. Convert each stated host event time to packet UTC using its scenario-assumed 150 ms lead. Check host and both socket ends, then baseline host/process/peer/window. Reject the nearest wrong-port event. Which second-session ownership record is absent? What source coverage is asserted versus unverified?
8. For each path, state the network observation, what the hypothetical card would change if verified, what it cannot establish, confidence in C2 for the matched traffic and one next action. Avoid an unsupported numerical score or a verdict on unsupplied Project 5.

Conclusion template: “Within [scope], packets show [behavior and references]. The approved-agent explanation is [verified/plausible/contradicted/untested] for [specific socket] because [source]. [Missing ownership or coverage] limits [claim]. C2 remains [qualified state]. Next request: [specific candidate process-network record plus approval/clock/provenance check].” In this kit the cards remain hypothetical, so do not label their ownership verified.

Independent assignment: apply the method to a separate authorized capture and permitted host records. Supply your own hashes and scope, not this answer key's values. If no such file is available, submit a collection/record request and explain what each requested item would test. Prepare the qualified conclusion for the next lesson, Deliver a C2 Investigation Brief.
