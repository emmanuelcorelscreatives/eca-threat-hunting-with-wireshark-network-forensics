# Data dictionary

practice.pcap: original15frame deterministic synthetic baseline. fixture-spec.json: exact base input. offline-builder.py: standard library Ethernet/IPv4/transport packet encoder, offline, no sockets, older output operation can overwrite.

column-hunt-spec.json: synthetic version1 input including base15frames plus3TCPopening frames, one TLS ClientHello and one two-answer DNS response. generate_column_hunt_fixture.py: versioned compatible generator/validator, uses exclusive output creation and checks exact capture hash plus decoded assertions; executable data is never accepted from the JSON specification. column-hunt-synthetic.pcap:20frames, including the intentionally incomplete TLS exchange and unmatched DNS response. expected-results.json: actual capture-bound results. The IPs are RFC5737 documentation space; names use .test.

base-fields.tsv/rich-fields.tsv: actual tab-delimited TShark output, all occurrences separated with commas; blank means no extracted field, not necessarily no traffic. actual-validation.json: author-executed deterministic rebuild and verification, tool version and platform. native-execution.json and native PNGs: bounded actual Linux4.4.0 isolated GUI evidence; independently reviewed receipts are separate. No actual learner, Windows or macOS execution is asserted.
