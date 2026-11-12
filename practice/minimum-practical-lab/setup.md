# Choose the Minimum Practical Lab

**Scope:** The saved demonstration has no course capture. Complete the planning worksheet without one. This kit additionally supplies a separate, explicitly synthetic six-frame DNS opening exercise. It is not evidence from the demonstration or a substitute for later case packs.

## Downloadable resources

Use `worksheet.md`, `answer-guide.md`, `DATA_DICTIONARY.md`, `practice.pcap` or its packet-equivalent `supplemental-dns-baseline.pcapng`. The offline source is `offline-builder.py` with its consumed input `executed-fixture-spec.json`; `practice-spec.json` preserves the initial authored design. Unzip the complete lesson kit before following relative paths. The intended public location for this kit is `practice/minimum-practical-lab/` in the Academy repository. Publication is a separate release step, not evidence of tool execution.

For installation, obtain the operating-system- and architecture-matched **current stable** distribution from https://www.wireshark.org/download.html. This upstream installer is not an Academy-owned download. The narration uses a Windows 11 x64 laptop and refers to a dated October 7, 2026 listing of 4.6.9; do not use that number as a current-version check.

## Workstation setup

1. Identify your OS and architecture, such as x64 or Arm64. On Windows, confirm the installer is the intended package and select **Wireshark and TShark** on Choose Components. Wireshark is the main workspace; TShark supports later repeatable offline work. The installer may offer Npcap, but opening saved files does not require live-capture setup.
2. On macOS, follow the official disk-image guidance for placing Wireshark in Applications and for command-line components. On Linux, check that your distribution's chosen packages include both tools. Do not infer installed versions or capture permissions from package selection; the next lesson checks them.
3. For an authorized supplied `.pcap` or `.pcapng`, use **Wireshark → File → Open**, not a live interface. Do not substitute unrelated traffic for an unavailable case file. Follow isolation rules for sensitive files: opening offline evidence does not guarantee the workstation is network-silent, and external name resolution may send DNS requests.

No VM, cloud account, live malware, production connection, or new collection is required. Optional collection belongs on an authorized controlled segment and is outside this exercise. Treat 8 GB RAM and 15 GB free storage as provisional planning targets; check final case-pack sizes before purchasing hardware. An optional virtual lab may need more memory.

## Reproduce the optional synthetic exercise

From this extracted directory run:

```sh
python3 offline-builder.py --spec executed-fixture-spec.json --output my-practice.pcap
editcap -F pcapng my-practice.pcap my-practice.pcapng
tshark -r my-practice.pcapng -T fields -e frame.number
```

Use new output filenames. The builder refuses to overwrite an existing file. The delivered `execution-proof.json` records actual execution of the same builder interface with a fresh `rebuild.pcap`, byte equality with `practice.pcap`, refusal of a second write, conversion to the delivered PCAPNG and matching field exports. Both delivered captures decode to six frames. The logs were produced on Ubuntu 24.04 with native TShark 4.4.0, not the narrated Windows laptop. No GUI execution, Windows installation or capture permission test is claimed. Opening through File → Open is a learner action, not a reported maintainer GUI observation.
