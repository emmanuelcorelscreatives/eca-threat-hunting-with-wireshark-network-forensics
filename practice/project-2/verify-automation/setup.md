# Set up the offline verification exercise

Use an offline working copy of this entire kit on Ubuntu 24.04 LTS with English-language, light-theme Wireshark. Actual CLI and GUI execution used native Wireshark/TShark 4.4.0; the installed mergecap used 4.2.2, recorded in automation/mergecap-version.stdout.txt. No historical case results or Windows validation are claimed. The command transcript records exact author-side paths; use your installed command names below. Keep the delivered captures unchanged.

From the root of your working copy:

```sh
sha256sum -c manifest.sha256
python3 tools/verify.py --root .
export WIRESHARK_CONFIG_DIR="$PWD/config"
tshark --version
wireshark --version
mergecap --version
tshark -C P2-Verify -r captures/sensor-a.pcap -Y dns -T fields -e frame.number
wireshark -C P2-Verify -r captures/sensor-a.pcap
```

The bundled profile is config/profiles/P2-Verify/preferences. The supplied execution used this profile in both GUI and TShark. Your installed versions can differ; record them and investigate differences before claiming equivalent results. The native screenshots are evidence of the supplied execution, not a replacement for your observation.

For GUI practice use File → Open to select the source capture named in an automated row. Check the profile, source identity, manifest hash and actual time coverage before applying the row's exact display filter. Use View → Time Display Format → UTC Date and Time of Day to compare UTC. The packet status bar distinguishes captured and displayed packets. Keep an unfiltered view for context. Go → Go to Packet refers only to the opened file's frame numbering. Open sensor-b separately for cross-source checks.

The prior batch outputs are supplied under automation/. command-transcript.json records every executed argument, return code and output file, including repeat runs and controlled failures. sensor-a-response.tsv and sensor-b-response.tsv use all field occurrences separated by |; a-first-cookie.stdout.txt and b-first-cookie.stdout.txt deliberately use the first occurrence only. Missing fields are empty TSV cells. Review export-settings.json before explaining a difference.

Optional deterministic rebuild, only into NEW scratch paths:

```sh
python3 tools/offline_builder.py --spec sensor-a-spec.json --output scratch/sensor-a.pcap
python3 tools/offline_builder.py --spec sensor-b-spec.json --output scratch/sensor-b.pcap
mergecap -I none -w scratch/merged.pcapng scratch/sensor-a.pcap scratch/sensor-b.pcap
```

The builder creates the output exclusively and refuses any existing file. Its two actual refusal logs are supplied. mergecap is not guarded by the builder: choose a nonexistent derivative path and never target supplied captures. The rebuilt source captures should match the two hashes in manifest.json. PCAPNG writer metadata may differ between versions; compare normalized packet bytes and timestamps before expecting a derivative file hash to match.

A direct export for comparison:

```sh
tshark -C P2-Verify -r captures/sensor-a.pcap -Y http.response -T fields -E header=y -E occurrence=a -E 'aggregator=|' -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e http.set_cookie
tshark -C P2-Verify -r captures/sensor-a.pcap -Y dns -q -z conv,tcp
tshark -C P2-Verify -r captures/sensor-a.pcap -Y dns -q -z conv,tcp,dns
```

These commands were executed in the supplied transcript; the first command above selects a subset of the fields in the preserved full export. The statistics deliberately compare an unfiltered TCP statistic with its separately filtered equivalent. A display filter does not automatically restrict every batch statistic.

## Corrected profile execution

The original profile contained an unsupported cosmetic preference. Original automation/ and native-v2/ receipts are retained as historical execution; the CLI warnings explicitly show that rejected setting. The current profile uses supported native defaults with no preference overrides. corrected-profile/ records fresh actual GUI and TShark execution with this exact corrected profile hash. All eight corrected-profile exports match their original TSV results byte-for-byte. The unchanged native-v2 screenshots retain their original narrow independent approvals; a separate new screenshot demonstrates current corrected-profile GUI selection.
