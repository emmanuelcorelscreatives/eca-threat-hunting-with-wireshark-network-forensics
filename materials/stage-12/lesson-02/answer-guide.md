# Answer guide — synthetic scenario

The following conclusions refer only to the authored synthetic scenario. The included `validation-execution.json` records an actual successful offline CSV check, including the stated counts. No packet builder or decoder is involved.

- The design contains 13 exchange rows: K00–K03, L01–L03, N01, N02, N03, and U01–U03. K00 models code 25 requesting pre-authentication, not a bad password. K01–K03 and U01–U02 model five separate code-24 Kerberos errors. K01 also has **one modelled resend of its own request**, not another exchange; the CSV cannot verify TCP retransmission.
- L01 and U03 model BindResponse 49 after BindRequest. L02 models SearchResultDone 49: the filter selects its result but does not turn it into a failed bind. L03 models BindResponse 0 after the configuration-update record; successful binding alone neither proves that the update caused it nor establishes compromise. N01–N03 model NTLMSSP_AUTH with no visible validation response. Their destinations are scenario assignments, not destinations established by event 4776.
- C01 records a 09:59 UTC password change for `svc-report`; C02 records a 10:03 UTC configuration update on 192.0.2.10. K01–K03 and L01, plus the possible N01/E04 correlation, fit an outdated-credential hypothesis at the approved source. K00 and L02 are not additional failed binds. Timing and ownership records do not prove the cause.
- U01, U02, U03, N02, and N03 involve the shared 198.51.100.44 egress whose origin and account approval are unverified; `user-demo` has no change record. Investigate these separately, including U01’s use of `svc-report`. A shared address cannot identify an individual endpoint or actor.
- The design has four 4771 rows (E01–E03, E05) with status `0x18`, plausible time/account/client-address counterparts to K01–K03 and U01. U02 has no supplied counterpart. Event 4771 records failed pre-authentication before ticket issuance; its event status must not be treated as a packet field. Three 4776 rows model bad password (E04), account locked (E06), and successful validation (E07). E04’s mapped workstation makes N01 a candidate, not a proven service destination. WKS-LAB-07 has no verified address mapping, so E06/E07 cannot be definitively paired with N02/N03. Event 4776 supplies no destination; E07 does not prove takeover.

**Defensible finding:** In this hypothetical, some authored results fit a stale service secret, while exchanges through a shared egress not documented as approved remain unexplained. There are no observed packets or established real-world failures in this kit. Request the verified change time, service configuration and process history, identity records for the scoped accounts/window, and contemporaneous address mapping. Preserve an inconclusive conclusion where attribution or responses remain unavailable.

## Worked distinction: resends and connections

K01 has one authored resend at 10:00:02.020000 UTC; K01, K02 and K03 are three separate modelled exchanges. This is scenario metadata. The CSV has no transport identifier, TCP sequence/acknowledgment values, packet payloads, capture completeness, or connection boundaries. It cannot establish that any resend is a TCP retransmission or count transport connections. For a separately authorized capture, compare transport/stream identity, sequence ranges, bytes and timing, request/response fields, and both-direction coverage. A repeated application request may use new transport bytes; a retransmitted segment need not represent a new login attempt. Conversation packet totals and graph peaks mix requests, replies, negotiation and retransmissions.

## Worked finding structure

**Scenario observations:** K01–K03 and L01 originate from the documented service source after C01; C02 precedes L03's modelled successful bind. Five exchange IDs use the shared egress. N01–N03 have no visible validation response in this dataset.

**Inferences:** stale configuration is a plausible explanation for part of the approved-source activity. The shared-egress activity merits separate correlation. Neither inference identifies an actor or establishes cause.

**Unsupported claims:** malware, successful takeover, attribution of WKS-LAB-07 to an IP, effectiveness of C02, actual TCP retransmissions, and a destination derived from 4776 cannot be concluded.

**Confidence limits:** high confidence in supplied CSV classifications, limited confidence in causal hypotheses; no confidence in real-world attribution because this dataset is synthetic and supplies no native host logs or packets.

**Next actions:** verify effective password/configuration times with service and identity owners, obtain process and service histories, check contemporaneous address translations and workstation mappings, and correlate authorized native logs/capture only within their recorded scope. Preserve unresolved results when replies or mappings are unavailable.
