# Setup and reproducible offline workflow

Use Python 3, Wireshark/TShark/capinfos 4.4.0 on Ubuntu 24.04, and an extracted copy of this directory. No secrets, privileges, network access or live capture are required. Both supplied PCAP names contain identical bytes. The scenario JSON describes the teaching cases; executed-fixture-spec.json is the exact builder input. Keep these distinct.

From this directory run:

```sh
python3 offline-builder.py --spec executed-fixture-spec.json --output rebuilt.pcap
cmp rebuilt.pcap practice.pcap
cmp practice.pcap http-header-form-supplemental.pcap
capinfos -c -s -a -e -u practice.pcap
tshark -r practice.pcap -Y 'http.request || http.response || http.content_type || urlencoded-form.key' -T fields -e frame.number -e ip.src -e ip.dst -e http.request.method -e http.host -e http.request.uri -e http.user_agent -e http.response.code -e http.content_encoding -e http.content_type -e urlencoded-form.key -e urlencoded-form.value
tshark -r practice.pcap -Y 'frame.number == 22' -x
```

The supplied execution-v1.json and named stdout files record actual local execution of these operations and richer field extraction, including byte-identical rebuilding. The builder refuses an existing output; use a new filename for a second rebuild. It supports --spec, not --scenario. It generates files only and never transmits packets.

In Wireshark choose File > Open and practice.pcap. Note the synthetic observation point, UTC window and two visible directions. Apply http.request, http.user_agent, http.content_type and urlencoded-form.key separately. Select a request, expand Hypertext Transfer Protocol in Packet Details, and inspect Packet Bytes. Compare the response on the same tcp.stream. For frame 22 use frame.number == 22 or tcp.stream == 3: this header-only final event decodes as TCP, so http.request will omit it. Inspect its TCP payload bytes. Filtering cannot recover its absent body or reply.

For a complete exchange, use Analyze > Follow > HTTP Stream if offered, then return to packets for direction, timing and frame citations. A stream is context, not a replacement for packet evidence. Native PNGs document actual filtered packet-list states; they do not claim expanded HTTP trees or a Follow dialog.

For the lecture homework, use only your own authorized working copy, record its collection point/host/window, and perform the same comparison. No own-capture homework has been performed on your behalf. Protected HTTP without authorized secrets cannot supply these application fields: mark unavailable, never infer from ports. Do not export or execute objects in this exercise.
