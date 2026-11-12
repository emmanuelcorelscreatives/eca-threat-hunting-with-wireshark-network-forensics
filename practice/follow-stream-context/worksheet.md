# Follow Stream without losing context

Work only with these authorized offline fixtures—or identify a different authorized source file. Do not combine the TCP and UDP cases.

## TCP file: __________  Time-display format/time zone: __________

1. Narrow hypothesis to test: __________. Prior display filter: __________. Selected packet’s recorded endpoints/protocol: __________.
2. Follow TCP. Transcribe only visible content, by captured direction; note whether Hex changes what you can establish: __________. Where does visible content appear to begin and end? __________.
3. Choose Close. Record the **actual** `tcp.stream` filter/index, relevant frame numbers, recorded times, Source → Destination, and gaps: __________. Does any row establish reception, processing, or intent? __________.
4. Restore your recorded prior filter; follow again and choose Back. What filter actually returns? __________. Clear it. What packets occur around the conversation, and do they demonstrably belong to it? __________.
5. Alternative explanation for a pause or incomplete view: __________. What capture coverage or other context would test it? __________.

## Separate UDP file: __________  Time-display format/time zone: __________

6. Hypothesis: __________. Follow UDP if available. Record visible **datagrams** by direction, not a continuous reliable byte stream: __________.
7. Close; record the actual `udp.stream` filter/index, frame numbers, times, and directions: __________. Clear the filter; describe nearby packets without assigning causality: __________.
8. Give three separate notes for each file: **visible content** __________; **recorded times and directions** __________; **collection or encryption limits** __________. State a narrow conclusion, confidence limit, and next useful action: __________.
## Reading order and bounded conclusion

9. Explain the difference between Follow TCP's expected byte order and the recorded packet list order. What do the supplied frames show? If a different capture has apparent repetition or a retransmission label, what would you check before diagnosing a cause? Do not invent repeated packets in this fixture: __________.
10. What do the first and last visible TCP payloads establish, and what do they leave unknown about the real conversation boundaries? Give at least one alternative explanation to test, rather than report as a finding: __________.
11. State explicitly what UDP does not guarantee about delivery and duplicates. If a direction is absent, can you distinguish a datagram never sent from one not captured? __________.
12. Give a narrow hypothesis, an evidence-limited example conclusion and a specific coverage or telemetry request that would test your alternative explanation: __________.
13. Optional separate authorized offline file: filename, authorization scope, actual local index, observations and limits: __________. Mark not performed if unavailable; never report the synthetic fixture as your own collection.
