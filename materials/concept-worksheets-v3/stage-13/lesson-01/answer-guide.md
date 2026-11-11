# Answer Guide and Reasoning Key

No packet-specific answer is supplied because no case packets were supplied. For the optional synthetic fixture, the only fixed result is a six-packet control total. Addresses, times, directions, classifications, and conclusions must come from actual inspection; document any mismatch rather than inventing an explanation.

## Checkable rubric

Mark each item only when supported:

- ☐ Source file, first/last packet times, duration, capture point knowledge, directions, gaps, and clock limits are recorded.
- ☐ Host identity cites an address-to-device mapping valid for the window.
- ☐ Peer/service identity is no more precise than the evidence permits.
- ☐ The display filter contains both verified endpoints and uses the matching address family.
- ☐ One protocol-appropriate contact rule is applied consistently.
- ☐ Responses, retransmissions, and continuations are not counted as fresh starts.
- ☐ Ambiguous or pre-capture starts are marked uncertain.
- ☐ Claims cite source frames; graph points and conversation rows are only navigation aids.
- ☐ A legitimate alternative and missing ownership/process context remain in play.
- ☐ The final result is support, weaken, or open—not proof of malware, command and control, process identity, timing regularity, or activity outside the capture.

## Practical-question key

1. A reply travels toward the host in an exchange already started; it is not a new host-initiated exchange.
2. A conversation row aggregates traffic between endpoints and may represent repeated contacts, one long exchange, or an incomplete exchange. A graph point sums packets within an interval and does not establish one callback.
3. A display filter changes only what Wireshark shows. It cannot restore traffic omitted during collection, a missing direction, packet loss, or activity outside file coverage.
4. Network timing alone does not identify the initiating process, ownership, authorization, or purpose. Reliable endpoint or service-owner context is required. Its rhythm alone cannot prove an attack.