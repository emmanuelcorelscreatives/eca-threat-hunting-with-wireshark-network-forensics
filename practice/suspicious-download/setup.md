# Setup and investigation

Read README.md and case-context.json before starting. Work in this extracted directory. Do not execute exported text objects. Preserve the supplied capture and write rebuilds/exports to fresh directories. The Python builder is offline and refuses existing output paths.

```sh
D=$(mktemp -d)
python3 offline-builder.py --spec fixture-spec.json --output "$D/practice.pcap"
cmp practice.pcap "$D/practice.pcap"
editcap -F pcapng "$D/practice.pcap" "$D/http-case.pcapng"
capinfos -c -a -e -u http-case.pcapng
python3 -m json.tool case-context.json >/dev/null
unzip -t inert-artifacts.zip
unzip -t investigation-workbook.ods
```

The Academy actually rebuilt the original PCAP byte for byte, tested existing-output refusal, converted the PCAPNG, decoded HTTP headers and bodies, exported objects with TShark and compared the two text objects byte for byte. See builder-and-package-execution.json, http-fields.stdout.txt, http-details.stdout.txt and http-export-byte-proof.json. The workbook was opened and rendered by LibreOffice headless and its actual sheet text checked. PCAPNG files generated in a different environment may include different metadata; use packet content and the PCAP rebuild comparison rather than assuming PCAPNG byte identity.

Open supplied http-case.pcapng in Wireshark. Inspect the entire packet list before filtering. Select View → Time Display Format → UTC Date and Time of Day. Record the original timestamp basis and capture scope, rather than inferring clock accuracy from the display choice. The actual native execution used an isolated Ubuntu/Linux Wireshark 4.4.0 process with UTC display and no live capture.

1. Apply `http.request || http.response`. Record each request/response pair and its TCP stream. Check the client mapping from case-context.json. Apply `http.request`, then `http.response`; inspect method, Host, URI, status, type and declared length.
2. Apply `http.response.code >= 300 && http.response.code < 400`. Inspect Location and find a later request to that URL. A redirect alone does not prove the redirected resource was requested. Record each actual frame and time separately.
3. Select frame 21 and use Analyze → Follow → HTTP Stream (Ctrl+Alt+Shift+H in this build). Inspect request and response, the declared 31-byte text body and both directions. Close the dialog and clear the resulting stream filter to return to the full capture. The native follow view and exact HTTP decode are supplied as reference evidence.
4. File → Export Objects → HTTP is the analyst export workflow. Select only the training objects and save to a fresh directory. Hash the copies and compare bytes against the supplied text files. These analyst copies are not evidence that a workstation saved a file. The supplied Academy export verification was executed with TShark, not a recorded click-through of this GUI export dialog:

```sh
E=$(mktemp -d)
tshark -r http-case.pcapng --export-objects "http,$E"
sha256sum "$E/review.txt" "$E/updater-note.txt"
cmp review.txt "$E/review.txt"
cmp updater-note.txt "$E/updater-note.txt"
```

5. Open endpoint-events.csv separately. Join by declared mapped host, UTC time, URL/path and size. Do not invent a content hash or measured clock offset for endpoint records. Compare the updater exchange with the same tests. Complete all worksheet sections and retain separate packet-frame and endpoint-event references.
