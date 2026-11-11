# Host-to-infrastructure timeline — worksheet

## Blank evidence template

Record source coverage and clock context **before** comparing times. Leave cells unknown until evidence is available.

| Source | Capture point and coverage | Display format and time zone | Known clock offset or unknown | Filter |
|---|---|---|---|---|
| ____ | ____ | ____ | ____ | ____ |
| ____ | ____ | ____ | ____ | ____ |

Keep events in separate lanes; add rows as needed. A displayed name is not, by itself, a captured DNS lookup.

| Lane | Source and frame/record reference | Displayed time and zone | Observed fields | Inference and limits |
|---|---|---|---|---|
| DNS query | ____ | ____ | ____ | ____ |
| DNS response | ____ | ____ | ____ | ____ |
| Outbound session | ____ | ____ | ____ | ____ |
| Application detail, if visible | ____ | ____ | ____ | ____ |
| Supporting record, if supplied | ____ | ____ | ____ | ____ |

| Rows compared | Link status | What the sources show | Alternative or missing link | Specific next record |
|---|---|---|---|---|
| ____ | ____ | ____ | ____ | ____ |

## Synthetic exercise—not a capture or observed finding

Suppose a description of an **upstream resolver-side** DNS query and response says the response contains several answer addresses. A separate **outside-capture** description reports a TCP exchange to an answered address, apparently later on its displayed clock, from a gateway-facing source. The clocks have not been compared. Neither a readable TLS server name nor decoded HTTP Host is provided. Client-side DNS, gateway translation, and process records are unavailable. A further session description contains no fresh DNS exchange. No files, frames, addresses, exact times, or software output accompany these descriptions.

1. What can each described source identify? Can you establish cross-source event order? **Answer:** ________________________________________________

2. Which separate timeline rows are warranted? Which fields and references remain unknown? **Answer:** ________________________________________________

3. Separate these claims: an address appeared in an answer; a session reached it; a specific service handled it; a specific process started it. How strong is the proposed DNS-to-session link? **Answer:** ________________________________________________

4. Give relevant alternatives for the gaps, then name the records that would test client identity, gateway attribution, and process attribution. **Answer:** ________________________________________________