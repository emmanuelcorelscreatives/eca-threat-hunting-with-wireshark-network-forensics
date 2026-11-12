# Native GUI evidence

These exact PNGs were captured from actual native Wireshark4.4.0 in isolated Ubuntu24.04 Xvfb with a fresh profile. They are Linux observations, not Windows11 proof. native-source-ledger.json binds the unchanged source PCAPNG, actual capture receipts, SHA256 and limited roles. Decode As tcp17454 NBSS was set at launch. The GUI did not start a capture.

00-full and01-protocol-filter show actual packet lists. Packet28 is the bind;35 manager response;36 service-open request;39 service response;43 shows the expanded STOPPED query result and WERR_OK;44 is the start request. Some views contain only a scrolled subsection; hidden fields remain CLI evidence in rpc-verbose.stdout.txt.

Both ORIGINAL native-conversations-initial.png and native-conversations-toggle.png show TCP selected, Limit checked and9 filtered packets out of46 total. The attempted outside-checkbox click did not change state. They are checked-state observations only.

The NEW native-tcp-right-columns-off.png visibly shows Limit unchecked,46 packets, directional packet counts24/22, Rel Start0.000000 and Duration0.1429. This exact corrected PNG is bound to the correctedUncheckedTimingSourceReceipt and independently passed review-v3/native_timing.json; it differs from the earlier failed off-named image retained in prior snapshots.

native-tcp-right-columns-on.png visibly shows Limit checked,46 total packets,19.57% filtered, directional packet counts5/4 and the same Rel Start0.000000/Duration0.1429. Its left-side packet count is clipped. The explicit9 filtered-packet value comes from the original checked-state companion screenshots and CLI, not a hidden cell in this timing image. Display-filter text and capture filename are not visible inside these dialog views; their association with dcerpc and the unchanged source relies on the source ledger.

The GUI retains underlying whole-conversation timing when counts are filtered. Independently filtered TShark conversation statistics have their own recorded start/duration, documented separately in answer-guide.md.99-restored clears the filter. These views convey no actual OS service action, learner-owned capture or incident attribution.
