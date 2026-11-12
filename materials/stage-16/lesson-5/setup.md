# Setup and native Wireshark walkthrough

Use a fresh folder and keep the downloaded original unchanged. This lab sends no traffic. Python 3 is required for the optional builder; TShark and capinfos must be installed for the verifier. Wireshark is the primary learner tool. The supplied proof was executed on Ubuntu Linux; native GUI evidence uses Wireshark 4.4.0, not Windows. A Windows learner can perform the same analysis locally; those Windows steps are instructions, not a claim of executed Windows validation.

1. Open `lookalike-traffic.pcapng`. Use File → Capture File Properties and record first/last packet times and packet count. Choose View → Time Display Format → UTC Date and Time of Day when comparing the scenario UTC records. Record observation point as an authored synthetic Ethernet link, not a measured collector. No capture-loss or interface provenance is established by these invented packet times.
2. Enter `dns` in the display filter. Record endpoint/resolver roles, query, response, answer and frame references. `dns.flags.response == 1` shows the three answers. Clear the filter with its clear button; packets were hidden, not deleted. The candidate has an answer with no shown subsequent connection.
3. Filter `tcp.flags.syn == 1 && tcp.flags.ack == 0`. Four rows are four separate connection starts. Inspect source/destination addresses and source ports, not just timing. Clear the filter. Filter `tls.handshake.type` to see eight Hello messages; expand Transport Layer Security in Packet Details. ClientHello SNI is visible. Only these openings are authored; there is no completed TLS negotiation or application payload to interpret.
4. Clear the display filter. Open Statistics → Conversations → TCP. Check the “Limit to display filter” control and record its state. Compare the four socket pairs, relative start, duration and directional packet counts. A short observed duration is bounded by the authored last packet, not proof communication stopped. Toggle the limit only with a documented filter and compare scope, then restore the unfiltered view.
5. Build a timeline from these packet observations, then test each host-card scenario separately. Use the dictionary for the scenario clock correction. Keep the comparison host's approval separate from candidate ownership. Capture times are synthetic design values, not proof a collector covered the long quiet interval.

Actual repeatable terminal checks, run from the kit directory:

```sh
python3 verify_fixture.py lookalike-traffic.pcapng
capinfos -a -e -c -s lookalike-traffic.pcapng
tshark -n -r lookalike-traffic.pcapng -Y 'dns || tcp' -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e dns.qry.name -e dns.a -e tcp.srcport -e tcp.dstport -e tls.handshake.type
tshark -n -r lookalike-traffic.pcapng -q -z conv,tcp
python3 build_fixture.py --spec fixture-spec.json --output rebuilt.pcapng
python3 verify_fixture.py rebuilt.pcapng
```

The builder refuses an existing output path and opens no socket. Its standard-library PCAPNG output is deterministic. `execution-proof.json` records an actual identical rebuild, overwrite refusal and rejection of a corrupted scratch copy; it is not a GUI verdict. `verification.json`, `capinfos.txt`, `decoded-fields.csv` and `conversations.txt` are actual executed results for the delivered capture, not commands waiting to run. Inspect the inventory SHA values before use. Never replace the original with a bad-input experiment.

The separate learner assignment is to analyse an authorized file covering the candidate endpoint/time with its own observation point, known gaps and permitted host records. Obtain permission before collecting any new traffic; this kit does not require live capture. Do not upload confidential case material or claim the Academy fixture is your own captured case. If records are unavailable, document that limit and request the exact missing candidate socket record rather than inventing it.
