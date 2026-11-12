# Setup and three-file intake

Use an isolated Ubuntu training environment with Bash, Python 3 and the Wireshark suite (Wireshark, TShark, capinfos and editcap). This kit was executed offline on Ubuntu 24.04 with the native Wireshark 4.4.0 development build recorded in the version logs. Check your installed versions; documentation does not prove them. No Windows execution is claimed.

Extract the whole ZIP into a NEW directory, change into its kit directory, and keep the supplied `original-{a,b,c}.pcapng` read-only. Do not run the builder against those originals. The executable `academy-offline-builder.py` and all three JSON specifications are now included. The earlier proposal used `materials/stage-08/lesson-03/` and separate downloadable prerequisites; this complete kit replaces that provisional packaging. Actual repository publication is recorded by the resource's commit metadata.

```bash
LC_ALL=C tshark -v
LC_ALL=C capinfos -v
mkdir student-work
cp -- original-a.pcapng student-work/s8l3-a.pcapng
cp -- original-b.pcapng student-work/s8l3-b.pcapng
cp -- original-c.pcapng student-work/s8l3-c.pcapng
for f in original-{a,b,c}.pcapng student-work/s8l3-{a,b,c}.pcapng; do
  printf 'SOURCE=%s\n' "$f"
  capinfos -H "$f"
done
```

Record each original SHA-256 and its working-copy SHA-256 in distinct fields. Compare with `verified-intake.csv`, which records the shipped files, and adapt the working path to `student-work/` in your own record. The historical `case-manifest.csv` intentionally retains blank hashes and its earlier path proposal. Its P1/P2 points and UTC collection windows are scenario metadata. Do not infer them from packets. Never discover inputs using a directory-wide capture search.

In Wireshark choose Edit → Configuration Profiles, select Default and record the selected name. Use the same profile in CLI commands. Our isolated GUI proof records Default; record any difference in your installation.

Optional reproducibility check: create a NEW temporary directory. The builder opens `--output` with exclusive creation (`xb`). An existing destination is refused with FileExistsError and remains unchanged. Choose a new output path or NEW directory after a refusal; never remove supplied originals to make a command succeed. Use new output names only:

```bash
mkdir rebuild
for x in a b c; do
  python3 academy-offline-builder.py --spec "source-$x.json" --output "rebuild/source-$x.pcap"
  editcap -F pcapng "rebuild/source-$x.pcap" "rebuild/source-$x.pcapng"
done
```

The deterministic classic-PCAP rebuild was actually checked twice per spec. PCAPNG container metadata may vary across versions; compare decoded events as well as hashes. The shipped originals and working copies are already materialized and byte-identical per source. Check errors before proceeding; a failed command is not an empty table.
