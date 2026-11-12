# Recorded native walkthrough

Actual Linux Wireshark4.4.0, isolated Xvfb, process TZ=UTC; supporting supplemental practice only. No Windows execution, live capture or saved-case evidence is claimed. `native-execution.json` binds each current PNG to the unchanged practice.pcap SHA and actual source screenshot.

`native-auth-filter.png`: exact lesson display filter; four matching frames. `native-bind-request.png`: actual frame11 LDAPv3 anonymous bind, empty name displayed by Wireshark as <MISSING>, simple authentication. `ldap-details.txt` contains the actual command dissection including the zero-length simple value. `native-bind-response.png`: actual frame12 result0 and request link11. `native-tcp-conversations.png`: actual TCP tab with five conversations and Limit to display filter unchecked. Displayed relative times are seconds since first frame, not absolute UTC strings; original epoch timestamps are supplied in decoded-fields.tsv. Screenshot direction/port labels are actual application output. These views demonstrate pairing and filtering, not account attribution or logon success. For result48 inspect frame20 in the supplied capture or ldap-details.txt.

No independent visual approval is asserted by this author-written note; exact reviewer receipts are maintained separately.
