# Establish Normal Windows Network Relationships — supplemental lab

This complete offline exercise uses synthetic Windows asset roles and synthetic SMB2 bytes. It is not an incident capture or a recording of Windows hosts. The saved lecture remains a method demonstration without a supplied historical case. The design intentionally contains only TCP opening handshakes, SMB2 Tree Connect exchanges and acknowledgments; no negotiation, authentication, file content, session teardown, process or identity evidence is present. Therefore a decoded success is an authored protocol result, not proof that a real server granted access.

Keep every kit file together. Start with setup.md, complete worksheet.md, then compare answer-guide.md. The canonical planned Academy location is `practice/windows-normal-relationships/`; use its README and complete ZIP as supplied by the course. Public publication status is established by the separate publication receipt, not this local text.

The hypothetical WS-ALPHA, FS-TEAM, MGMT-OPS and WS-BRAVO mapping is defined in asset-inventory.csv. Those roles are scenario context, not OS fingerprints from the packets. scenario-plan.csv retains the original design; measured results are in execution.json and command outputs. approved-activity.csv contains exercise-only approval records.

The native screenshots were actually obtained using Linux Wireshark 4.4.0 and an isolated desktop. PowerShell Import-Csv was actually executed with PowerShell on Linux. Neither is evidence of a Windows-host test. Windows learners use the same cross-platform file, filters and PowerShell cmdlet; record their own versions and any platform differences. No production connection, credentials or packet capture privileges are needed.

Capture SHA-256: `de7c2dc03a792faaa9e0075844d9c26209275d12fa977e0723fd93b6864b8e8f`.
