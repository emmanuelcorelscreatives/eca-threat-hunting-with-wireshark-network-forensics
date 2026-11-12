# Supplemental offline practice: low-volume and staged transfers

This is a **separate, labelled synthetic Academy exercise**, not the historical case discussed in the unchanged lecture. The lecture supplied no case capture or case packet results. The fixture lets students establish repeated, small, asset-sourced exchanges and test a possible staging clue; it does **not** establish a local file operation, an encrypted transfer, authorization, or sensitive-data loss. Use only an authorized offline copy. The kit is assembled but **not version-published**; the proposed repository path and URL in the earlier draft are not a verified commit or download location.

## Packaged resources and provenance

Use the packaged `practice.pcap`, `offline-builder.py`, **`executed-fixture-spec.json`**, `case-context.csv`, these Markdown files, and the supplied `*.stdout.txt`/`*.stderr.txt` execution logs. `executed-fixture-spec.json` is the deterministic builder input actually used. Do not assume that an earlier `fixture-spec.json` alias exists or has identical contents. The packaged builder has no `--check` option and overwrites its `--output` path.

The assembly reports an identical deterministic rebuild: builder SHA-256 `2e3f5f0f28b7f44cc7f0a84f8fec600ed2298db85a683619cb835c6be44ae98e`, executed-spec SHA-256 `1955a6aeecfa57ae15b1efc480b8b0e40b633f7ad38f4e7789542cf81d1f3944`, and capture SHA-256 `bf5c781e12dc5fb86b65b724464bb70e944b1eb483910fd00facad9d2004f0bd`. `capture-info.stdout.txt` independently reports the capture hash, 2,585-byte PCAP, and 34 packets. These identify *this fixture*, not a narrated-case exhibit.

On an offline Linux workstation, have Python 3 and Wireshark available. The supplied read-only logs were produced with pinned **TShark 4.4.0 Linux** tools, including `capinfos`. Separate native Linux GUI evidence is now included; no Windows procedure is claimed. Record your own tool versions, workstation time zone, and any differing decode. Do not run TShark as root merely because the supplied stderr logs contain a root-user warning.

For an optional **new** local build, preserve the packaged PCAP and write into a fresh directory. The following student shell invocation is a suggested reproduction path, **not** one of the logged commands:

```sh
outdir="$(mktemp -d)"
python3 offline-builder.py --spec executed-fixture-spec.json --output "$outdir/practice.pcap"
# If available, compare the two files with sha256sum; retain the original.
```

Expect the reported SHA-256 above if the inputs and builder match. Do not point `--output` at packaged `practice.pcap` or an existing evidence file. On Windows, choose a separate new output directory by an appropriate local method; neither Windows commands nor GUI behavior have been verified here. The builder authors packets offline and sends no traffic.

## Reproduce the supplied read-only Linux checks

Run from the directory containing the packaged PCAP. These are the **arguments actually executed** in the supplied logs; bare `tshark` and `capinfos` below stand for the pinned tools invoked there by absolute path. Their corresponding named stdout files preserve the results. Re-running them elsewhere is a new check, not a claim of identical platform behavior.

```sh
capinfos practice.pcap
tshark -r practice.pcap -q -z conv,tcp
tshark -r practice.pcap -q -z conv,ip
tshark -r practice.pcap -q -z io,phs
tshark -r practice.pcap -Y _ws.malformed -T fields -e frame.number
tshark -r practice.pcap -Y 'ip.src == 192.0.2.25 && ip.dst == 198.51.100.77' -T fields -e frame.number -e frame.time_utc -e tcp.stream -e frame.len
tshark -r practice.pcap -q -z 'io,stat,60,ip.src == 192.0.2.25 && ip.dst == 198.51.100.77' -z 'io,stat,10,ip.src == 192.0.2.25 && ip.dst == 198.51.100.77'
```

The executed all-frame extraction, saved as `all-frames.stdout.txt`, used `tshark -r practice.pcap -T fields -E header=y` followed, in order, by `-e` for `frame.number`, `frame.time_epoch`, `frame.time_utc`, `frame.len`, `frame.cap_len`, `frame.protocols`, `ip.src`, `ip.dst`, `tcp.stream`, `tcp.srcport`, `tcp.dstport`, `tcp.seq_raw`, `tcp.ack_raw`, `tcp.len`, `tcp.payload`, `dns.qry.name`, `dns.qry.type`, `dns.a`, `http.request.method`, `http.request.uri`, `http.host`, `http.response.code`, and `http.file_data`. Use its header to interpret empty fields. `frame.time_utc` produces a human-readable **UTC** date/time, not an ISO-8601 string; `frame.time_epoch` is decimal seconds since the Unix epoch. The pinned 4.4 tool inventory found `frame.time_iso8601` **unsupported**: the older field-extraction proposal containing it did not run and must not be presented as a successful check.

Read `case-context.csv` before opening the capture. Its proposed interruption and shift remain fictional scenario context. Follow the native-validation.md evidence map for actual GUI observations and their precise limits; perform your own steps and record any platform differences. UTC is the author workstation process zone, not an inferred asset zone. UDP boundary markers extend the file span without proving continuous collection.

## Earlier draft and outstanding lesson scope

The earlier proposal named `build_fixture.py --check low-volume-staged-supplemental.pcap` and checks against `low-volume-staged-supplemental.pcap`; neither the generator, its `--check` behavior, nor that named output is established by this package. It also proposed `python3 offline-builder.py --spec fixture-spec.json --output practice.pcap`: that exact alias-based invocation is not the verified rebuild and would overwrite the packaged output. Its `10.19.3.25` address belongs to an illustrative, unavailable case example; the packaged builder accepts documentation addresses and this fixture uses `192.0.2.25`. Preserve these as **unimplemented draft proposals**, not operational substitutions or historical findings. If a curriculum requires that named generator, output, or check, implement and verify it separately.

The original practice.pcap has no TLS packets or observed endpoint file activity. The additional actual-tls-staging.pcap and actual-host-file-events.json now supply a separate encrypted-flow and observed host-staging exercise. Never transfer those findings into the documentation-address case. A TCP handshake alone is not a TLS handshake, and the original HTTP PUT is not evidence of a local file operation. Original owner schedules and destination authorization remain absent.

## Actual loopback TLS exercise

Open actual-tls-staging.pcap offline. The actual author collection used Ubuntu 24.04.5 LTS and loopback 127.0.0.1 only. Read actual-collection-receipt.json, actual-host-file-events.json, actual-tls-fields.stdout.txt and actual-tls-protocols.stdout.txt. Three connections use server port 57371, so address direction alone cannot separate same-host client and server: use TCP ports and stream IDs. Filter `tcp.port == 57371`, then `tls`, then inspect each TCP stream and TLS record metadata. Do not install keys or decrypt. Compare client ephemeral-port sources with server-port sources. The apparent TLSv1.2 ClientHello label does not establish the negotiated version; later records and the client host log identify TLSv1.3.

The delivered build-low-volume-actual-v1.py records the collection procedure. It binds a local server and captures loopback traffic; it is a preserved historical author procedure for inspection only, with author-specific paths and incomplete failure cleanup. Do not run or import it. It can overwrite output and leave capture/server processes active after failure. No optional live-collection reproduction is assigned. It is not an offline deterministic rebuild. The original offline-builder.py remains the deterministic network-free rebuild for practice.pcap only.

The actual TLS collection has abrupt client RST endings after host-confirmed receives, not orderly complete TLS/TCP shutdowns. Inspect starts and encrypted records without inferring complete session coverage or graceful closure. The host receive logs support their recorded slices, not complete file transfer.
