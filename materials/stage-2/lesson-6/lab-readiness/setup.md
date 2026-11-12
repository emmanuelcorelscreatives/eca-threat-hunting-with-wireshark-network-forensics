# Troubleshoot the lab before you hunt

Use this kit with Stage 2, Lesson 6. It provides a known-good **synthetic shared Academy reference**, plus a separate six-packet troubleshooting exercise. Neither is a historical incident or evidence of compromise. No traffic is sent by the offline tools.

Extract the complete kit into a new folder. Install Wireshark (GUI) and its TShark/editcap/capinfos utilities, and Python 3. The recorded worked example uses native Wireshark 4.4.0 on Ubuntu 24.04.5 LTS with `TZ=UTC`; it is not Windows execution. Your menus and local time zone can differ. Use a disposable profile for this exercise.

## Known-good reference

Open `lab-reference.pcapng` using File > Open. This is the actual PCAPNG conversion of the unchanged public `practice/dns-baseline/captures/synthetic-dns-baseline.pcap`, supplied here as `shared-dns-baseline.pcap`. The complete unchanged shared directory is in `unchanged-shared-dns-baseline.zip`; `shared-source-provenance.json` records its exact public commit and Git blob identities. Keep that file separate from `practice.pcap`.

`reference-checks.json` contains measured reference answers: six packets, IPv4 Endpoints `{192.0.2.10,192.0.2.53}`, all packets with display filter clear; UTC window 2026-11-11 00:00:00.000000 through 00:01:00.020000. DNS answer 198.51.100.20 is not an IPv4 packet endpoint. Follow `worksheet.md` before reading the answers.

From the extracted kit directory, verify the supplied reference without overwriting it:

```sh
python3 prepare_reference.py --check
capinfos -c -a -e lab-reference.pcapng
tshark -n -r lab-reference.pcapng -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e dns.flags.response -e dns.qry.name -e dns.qry.type
tshark -n -r lab-reference.pcapng -q -z endpoints,ip
tshark -n -r lab-reference.pcapng -Y 'frame.number == 999999' -T fields -e frame.number
```

All five commands ran successfully in the worked example; exact stdout/stderr and arguments are in `reference-check-*.txt` and `reference-execution.json`. The last command returns no frame rows. The GUI independently checks the filter, counts, time display, numeric addresses, profile and endpoint scope; see `native-validation.md` and the actual screenshots.

To build another reference, use fresh output names so existing work is preserved:

```sh
python3 prepare_reference.py --source shared-dns-baseline.pcap --output my-reference.pcapng --manifest my-reference-checks.json
python3 prepare_reference.py --check --source shared-dns-baseline.pcap --output my-reference.pcapng --manifest my-reference-checks.json
```

These commands replace the old draft proposal for a `lessons/06-troubleshoot-lab/tools/prepare_reference.py --source-dir ...` interface. The delivered script takes an explicit source capture, verifies its approved SHA-256, converts it, compares every decoded row, and refuses existing output paths. Other captures require their own independently supplied checks; do not edit the approved hash to force a match.

## Separate practice capture

`practice.pcap` contains three synthetic DNS query/answer pairs using two clients and a DNS server. It is **not** the shared known-good reference. Rebuild to a fresh output path:

```sh
python3 offline-builder.py --spec fixture-spec.json --output my-practice.pcap
```

The actual deterministic rebuild matched all 628 delivered bytes. Reusing the same output name was tested and refused without changing the file; see `builder-safety-and-rebuild-execution.json`. `all-frames.stdout.txt` provides the actual decoded fields. `assembly-manifest.json` is a preserved historical assembly receipt, not the current inventory: it describes old pre-repair guides and builder. Use `current-kit-inventory.json` for the current delivery.

## Optional live assignment

Use `optional-live.md` only with your approved isolated lab and capture plan. Offline success does not prove live-interface visibility. No live interface or exchange is required to finish the offline reference exercise, and no learner live result is claimed here.

The delivered `current-kit-inventory.json` is an inventory envelope: its `files` array covers every other delivered kit member and excludes the envelope itself to avoid a self-referential hash. The independent review binds the envelope separately by SHA-256, and publication/ZIP audits cover it as a delivered file.
