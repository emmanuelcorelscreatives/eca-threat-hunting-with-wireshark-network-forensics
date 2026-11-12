# Checked synthetic lab solution

These citations come from actual TShark 4.4.0 dissection of the delivered synthetic files on Ubuntu, not a GUI recording or a historical case. Times below are UTC on 2025-02-20. Refer to executed-proof.json and decoded TSVs for complete fields.

## client-facing.pcap (24 frames)

Frames 1–3 begin the first .42 TCP handshake at 12:00:00.000, before visible DNS. Query 4 / reply 5 (ID 20481 / 0x5001) pairs client 192.0.2.30 with resolver 192.0.2.53 for portal.academy.test at .100/.120. Reply 5 has portal.academy.test CNAME edge.academy.test TTL30; edge.academy.test A 198.51.100.41 TTL60, A 198.51.100.42 TTL90, and AAAA 2001:db8::41 TTL60. All address records belong to edge, not directly to portal. The alias link connects them.

Query 6 / reply 7 (ID20482 / 0x5002) at .200/.220 is mirror.academy.test A 198.51.100.42 TTL60. Therefore the .42 match is compatible with more than one name.

|Destination|First client SYN|First after initial answer|Interpretation|
|---|---|---|---|
|198.51.100.41|8,12:00:00.300|8|Address match after reply5|
|198.51.100.42|1,12:00:00.000|14,12:00:00.500|Frame1 precedes DNS; frame14 follows both portal and mirror replies|
|2001:db8::41|11,12:00:00.400|11|IPv6 client 2001:db8::30; same synthetic workstation role from plan, not proof linking real IPv4/IPv6 identity|
|198.51.100.43|None in this file|None|Offered in reply18; leave in history without inventing a session|

Query17 / reply18 (ID20483 / 0x5003) at 12:00:01.000/01.020 changes portal's visible answer to A .43 TTL60. SYN19 at 12:00:01.200 contacts .41 from the older reply5, not the new .43. SYN22 at 12:01:02.000 contacts .41 61.880 seconds after reply5, beyond that record's 60-second TTL. This warrants cache/lookup investigation; it establishes neither stale cache use nor hostname. Reply5 is the beginning of the visible portal answer history, not proof that earlier answers never existed. Every SYN here has its reversed SYN/ACK and final ACK in the next two frames. Port443 carries no TLS or application hostname evidence.

## upstream-only.pcap (5 frames)

Query1 / reply2 ID30481 (0x7711), 12:00:00.100/.120, shows resolver192.0.2.53 asking upstream203.0.113.53 for portal, A .41 TTL60. Client192.0.2.30 begins TCP to .41 in frame3 at .300. The workstation requesting the DNS lookup is unresolved; the upstream exchange does not identify it. Request client-facing DNS or a client-identifying resolver record matching the timing. A later address match alone cannot supply attribution.

## no-dns.pcap (3 frames)

Frame1 at 12:00:00.300 is a client .30 SYN to .41; frames2/3 complete its handshake. No DNS packet is present. The capture contains no observed query/reply and cannot establish the name selected, absence of any earlier lookup, or the resolution mechanism. Request an earlier window or client lookup/application record. A displayed name supplied by Wireshark's outside resolution would not change packet evidence.

## Limited earlier supplemental exercise

limited-practice.pcap has 20frames and is a separate fixture: query/reply pairs4/5,6/7,8/9,10/11; SYNs1,12,15,18. Its .41 late SYN18 is 61.090 seconds after reply5, TTL60. Each reply contains a single A and there is no CNAME/AAAA. Do not transfer full-pack frame numbers to it.

Example evidence note: In synthetic client-facing.pcap, reply5 to query4 provides edge .41 through portal's CNAME at 12:00:00.120; client SYN8 reaches .41 at .300, 0.180seconds later. The address and order are observed with high confidence in this fixture. The application hostname is unresolved; another hostname or earlier information could explain the destination. Seek application/endpoint name-selection context. Neither intent nor suspiciousness follows from the address match. The learner must write a distinct note using their own authorized capture for homework.
