# Data dictionary

`fixture-spec.json` is a synthetic version 1 offline input. Ordered UTC event timestamps span 2025-01-16 12:00:00.000000 to .060000. TCP has ports, flags, raw sequence/ack and payload; DNS includes name, transaction ID and answer. ARP request has sender/target IPv4 addresses but no IPv4 packet header. All IPv4 addresses and the `.test` DNS name are documentation data. Derived unicast MAC addresses are `02:00` plus IPv4 octets; ARP uses broadcast Ethernet destination and zero target hardware address.

`fixture-manifest.csv` maps `case_id`, checked `frame_number`, authored `offset_ms`, event `kind`, endpoint design and role. `expected-membership.json` is the independent expected frame map used for comparison; `actual-verification.json` records independently decoded rows and observed selection. Case IDs are labels, never portable packet references. Capture hash binds this mapping to one file. No row is a real collection-coverage claim.
