# Positive and negative display-filter controls

This complete supplemental exercise uses seven deliberately synthetic Ethernet frames. It is authorized offline training material, not the saved lecture's working capture, a real incident, or a learner's capture. No live capture or network access is required. The original lesson's separate authorized-capture notebook task remains in `worksheet.md`.

Download every file in this directory together. Requirements: Wireshark or TShark, and Python 3 standard library; no pip packages are needed. From this directory:

```sh
python3 verify.py --capture practice.pcap
python3 offline-builder.py --spec fixture-spec.json --output rebuilt.pcap
python3 verify.py --capture rebuilt.pcap
```

The builder refuses to overwrite an existing output. Select a new path to repeat a build. The seven-frame file replaces the earlier six-frame draft. `offline-builder.py` and `verify.py` replace the draft's unimplemented Scapy scripts, requirements file and mixed-ipv4-synthetic.pcap name. The provided download is `practice.pcap`; do not execute obsolete draft commands. This offline builder sends no packets.

First complete predictions in the worksheet. Then open `practice.pcap` in Wireshark, clear the display filter and confirm seven total frames. Apply each exact expression below, record the visible frames and displayed/total counts, clear and reapply the host filter, and test exclusions. Native Ubuntu/Linux evidence is supplied; it does not assert Windows validation. The GUI steps operate on the same decoded fields as the executed TShark checks.

```text
ip.src == 192.0.2.10
ip.addr == 192.0.2.10
tcp && ip.addr == 192.0.2.10
ip.src!= 192.0.2.10
not (ip.src == 192.0.2.10)
```

The checked answer key and `actual-verification.json` refer only to the supplied capture SHA-256 9968bbde733cef6879415e2e0ec1ddb8545aa450e816a9e652dd1fc2fd46d107. `fixture-manifest.csv` maps synthetic case IDs to actual decoded frame numbers in that file. On a different authorized capture, substitute an in-scope host and record fresh file/frame references; never transfer these answers. Missing controls remain untested. Display filters cannot establish collection coverage or legitimacy.
