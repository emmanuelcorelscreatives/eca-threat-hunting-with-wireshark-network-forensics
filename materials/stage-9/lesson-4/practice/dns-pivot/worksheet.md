# Pivot worksheet

Hypothesis: the client that received a DNS answer later contacted an offered address. File: ___; observation point: ___; capture window: ___; display zone and UTC conversion: ___.

1. Record query/reply frame numbers, exact question, ID, client/resolver endpoints, reply UTC, each alias owner and target, address owner, A/AAAA value, TTL and answer frame. Trace the alias chain; retain all addresses.

|Query/reply frames; ID; question|Client → resolver|Reply UTC; alias chain|Owner; address; TTL; frame|
|---|---|---|---|
|___|___|___|___|
|___|___|___|___|

2. For every returned IPv4/IPv6 address, record first observed client packet and first later candidate, source file, frames, direction, UTC and whether the actual initiating SYN is visible. Check surrounding packets and Conversations. Keep unused addresses in answer history.

|Address|Answer time/frame and history position|First observed packet|First later session/SYN; direction; UTC|
|---|---|---|---|
|___|___|___|___|
|___|___|___|___|
|___|___|___|___|
|___|___|___|___|

3. Identify the pre-answer .42 connection, the older-answer .41 connection after the newest .43 reply, shared mirror/portal .42, the unused .43 and the IPv6 candidate. Compare the late .41 SYN with its TTL. State why each address match leaves application hostname uncertain and why TTL does not prohibit a connection.

4. Repeat for upstream-only.pcap and no-dns.pcap. Which endpoint requested the upstream resolver's answer? What is actually absent in each file? Request the client-facing lookup or client-identifying resolver record, earlier time window, endpoint/application record or cache history needed to test the uncertainty.

5. Write a short evidence note with hypothesis, scope, source file, query/reply/session frames, UTC order, answer history, observed/inferred/uncertain claims and confidence for each. Name one plausible competing explanation and the specific next evidence that could distinguish it. An address match does not establish application intent, compromise or suspiciousness.
