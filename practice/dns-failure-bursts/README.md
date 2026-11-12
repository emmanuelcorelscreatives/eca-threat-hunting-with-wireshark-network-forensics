# DNS failures, bursts and repeated lookups

This is a separate Academy-designed, offline synthetic exercise for Stage 9, Lesson 2. It supplies two actual, independently checked binary captures: `fixtures/client-facing.pcap` (22 frames) and `fixtures/upstream.pcap` (10 frames). The saved lecture describes a method and has no original incident capture; these new samples are not that incident and establish no real application or compromise.

Start with [setup.md](setup.md), work through [worksheet.md](worksheet.md), then compare [answer-guide.md](answer-guide.md). The captures have separate collection points and windows. Never merge them or use a single `practice.pcap` alias for both views. `transactions.csv` is the author's input design, not endpoint telemetry. `verification.json` maps each authored row to actual generated frames. The native evidence and CLI transcripts document actual Academy validation; the learner should perform the investigation independently and record observations from their own run.

The author executed Python 3 and TShark/Wireshark 4.6.9 on Ubuntu 24.04.5, using an isolated display and profile. Native GUI captures show actual application state, not reconstructed UI. The lecture's Windows 11 context remains unchanged; no Windows execution is claimed. No live capture, network transmission, credentials, or endpoint logs are needed. Source addresses use documentation ranges and names use `.test`.

Deliver a transaction table, failure graph comparison, competing explanations, confidence limits, and one specific corroborating-record request. An unresolved outcome is valid. If any verification fails, stop before relying on packet counts or answer keys.
