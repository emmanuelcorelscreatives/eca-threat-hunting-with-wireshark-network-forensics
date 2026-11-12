# Unusual DNS names and TXT: independent offline Academy lab

This kit supplements the lecture without replacing its unavailable historical capture or the learner's own authorized-capture homework. Both PCAPs are explicitly synthetic and send no traffic. The original A-only `practice.pcap` is retained unchanged; use **practice-v2.pcap** for the complete lab. The v2 adds a real encoded TXT question and matching answer, unlike the separately labelled hypothetical `txt-example.csv`.

Use Wireshark/TShark 4.4.0, Python 3.10+ and an authorized local working directory. The lecture demonstrates Windows 11, English, light theme. Supplied execution evidence is Ubuntu24.04 native Linux4.4.0; no Windows execution is claimed. Python commands also provide a complete portable workflow, replacing the older proposed unimplemented PowerShell checker. On Windows use `py -3` in place of `python3`, and a full TShark executable path if needed. Run commands from the extracted kit folder.

Keep the supplied originals separate from working copies. This read-only checker consumes the original without modifying it:

```text
python3 verify-dns-evidence.py --capture practice-v2.pcap --domain edge.academy.test --start 2025-03-10T12:00:00Z --end 2025-03-10T12:00:32Z --tshark tshark
```

For an independent offline rebuild, select an unused output filename (existing files are refused):

```text
python3 offline-builder-v2.py --spec fixture-spec-v2.json --output student-rebuilt.pcap
```

The builder needs only Python's standard library. It does not invoke TShark or send packets. Open a separate copy using Wireshark File → Open. Enter `dns`; inspect decoded questions and matching answers. See the worksheet for the full task and the answer guide after attempting it. Supplied native GUI views are explicitly Linux supplementary evidence and do not claim Windows controls were executed. All `*-v2` execution logs relate to v2; unqualified legacy logs and assembly-manifest.json relate to the original13-frame A-only capture.

Use your own authorized offline capture for the lecture's separate homework. Replace the checker capture/domain/window values with your documented scope; keep absent evidence blank. These synthetic endpoints do not identify any workstation, user or process. No public download availability is asserted until publication audit succeeds.
