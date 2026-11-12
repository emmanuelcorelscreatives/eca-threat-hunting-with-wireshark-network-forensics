# Setup and reproducibility

Use an isolated Ubuntu workstation with Python 3 and Wireshark/TShark 4.4.0. No pip dependencies are needed. Python's standard library builds the offline capture. Keep the original unchanged and analyze a working copy. Do not visit the .test URLs or replay packets.

From this folder, reproduce to a new path:

```sh
python3 build_capture.py --spec fixture-spec.json --output rebuilt.pcap
cmp practice.pcap rebuilt.pcap
sha256sum practice.pcap rebuilt.pcap
capinfos -c -a -e -u practice.pcap
```

A fresh path is required: the builder refuses existing files. The shipped execution-proof.json proves a byte-identical second build, checksum, malformed-frame and TCP loss checks. capinfos above is a learner cross-check; the shipped exact executed commands are in execution-proof.json and actual-command-results.txt.

Open a copy of practice.pcap in Wireshark. Confirm the client and time bounds from README.md. Apply `http.request`, then `http.response`, then `http.location`. Record the status, request/response references, stream, Host and path for every exchange. Expand HTTP details; when automatic request-response links exist, check them. Otherwise verify direction, the conversation, complete request and response content and ordering. Do not pair messages by proximity alone.

Under Statistics → HTTP → Request Sequences inspect suggested relationships. Select a packet and use Analyze → Follow → TCP Stream to inspect the actual exchange. Clear the resulting stream filter before looking for another connection: each exchange in this fixture has a separate stream. These are student workflow instructions, not a claim that the shipped CLI logs executed GUI menus. Resolve relative Location values against the original URL; a later request must match host and path and follow in time. Inspect `(http.response.code == 200 || http.response.code == 206)` as leads for delivery; status alone proves neither a complete object nor saving or execution.

For the independent command-line cross-check:

```sh
tshark -2 -r practice.pcap -Y 'http.request || http.response' -T fields -e frame.number -e tcp.stream -e http.request.method -e http.host -e http.request.uri -e http.response.code -e http.location -e http.request_in -e http.response_in
```

The supplied two-pass TShark 4.4.0 decoding provides automatic pairing references for all eight pairs, including request 59 and response 61 in stream 5. Check those references against the unique conversation, packet content and ordering; automatic links support the pairing but do not establish navigation causality.
