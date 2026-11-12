# Checked answer guide — synthetic exercise

Actual TShark 4.4.0 decoding of the bundled PCAPNG found **15 frames, eight IPv4 endpoints, no IPv6 endpoints**, UTC bounds **2025-01-16 12:00:00.000000 to 12:00:04.010000**, duration 4.010 seconds. No frames matched `_ws.malformed`; captured and original lengths match for every frame. These checks are limited to this file, not a universal protocol or topology guarantee. Packet observations below are decoded facts; proposed roles and classification come from the separately authored synthetic inventory.

| Address | Observed frames | Inventory | Scenario classification and next record |
|---|---|---|---|
| 192.0.2.10 | 1–7 | I01, dated workstation | Supported; retain the dated snapshot source. |
| 192.0.2.53 | 1,2,8–15 | I02, dated resolver | Supported by inventory; DNS traffic alone does not establish assigned role. |
| 192.0.2.1 | 3,4 | I03, dated network device | Supported by inventory; an echo reply does not establish role. |
| 192.0.2.20 | 5–7 | I04, dated server | Supported by inventory; a DNS answer or port 443 does not prove an approved service or TLS exchange. |
| 192.0.2.77 | 8,9 | I05, undated workstation | Provisional; request capture-time assignment dates or snapshot. |
| 192.0.2.78 | 10,11 | I06 workstation ends Jan 15; I07 server starts Jan 17 | Unknown during Jan 16 capture; preserve both records and request assignment history for the gap. |
| 192.0.2.90 | 12,13 | I08 workstation; I09 network device | Conflicting overlapping records; retain both owner entries and ask both teams to reconcile. |
| 192.0.2.44 | 14,15 | None | Unknown; request dated inventory covering this segment, not an intruder verdict. |

Worksheet controls: eight address rows; four supported, one provisional, one conflicting and two unknown classifications. `expected-results.json` gives each address's checked first/last epoch time and exact frame list. I10's 192.0.2.99 server is not observed; duration, authored event selection and limited visibility are alternatives to disappearance. All asset labels, teams, roles and sources are fabricated scenario records. None independently confirms a real assignment. Frames 5–7 contain only a TCP handshake with no application payload; do not infer TLS or an actual approved service.
