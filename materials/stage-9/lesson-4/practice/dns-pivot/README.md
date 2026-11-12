# DNS answer to connection lab

This complete Academy lab uses explicitly synthetic, deterministic packets authored offline. It supplies three distinct viewpoints to practice the saved lesson's method. These are not historical incident evidence or the learner's own capture. No traffic is transmitted. No accounts, production traffic or keys are needed.

Extract the whole ZIP and keep the folder structure. From the extracted root, open `practice/dns-pivot/fixtures/client-facing.pcap` in Wireshark through File → Open. The other files are `upstream-only.pcap`, `no-dns.pcap`, and the older `limited-practice.pcap`. The 20-frame limited exercise is supplemental; the 24-frame client-facing file is the full alias/IPv6 exercise. Never mix their frame citations.

Use Wireshark as the primary tool. Set View → Time Display Format → UTC Date and Time of Day, or record your actual local display zone and convert to UTC. Record the file, observation point, first and last packet time. Apply `dns.flags.response == 1`, then `dns.qry.name == "portal.academy.test"`. Match the client's request and reply by transaction ID, endpoints, direction, question and time; inspect linked frames where available. Expand Domain Name System → Answers, and trace CNAME owner to address owner, recording every A/AAAA and per-record TTL.

For each address use `ip.src == 192.0.2.30 && ip.dst == 198.51.100.41`, substituting `.42` and `.43`. Check the first packet and surrounding frames to distinguish a prior session from a later one. For IPv6 use `ipv6.src == 2001:db8::30 && ipv6.dst == 2001:db8::41`. Open Statistics → Conversations, select TCP and inspect start times and endpoint pairs, then return to the actual initiating SYN. Summary rows cannot identify the application's hostname. Address placeholders in the lecture are not these fixture findings.

Complete worksheet.md before consulting solutions.md. Compare all offered addresses, aliases, the earlier and later portal answers, mirror's shared address, and contact beyond the observed TTL. Keep observed address/timing links separate from hostname inference. TTL concerns caching, not a connection deadline. A pre-lookup connection may reflect earlier information; the file cannot prove it. Application, endpoint or cache evidence would be needed to select a hostname or explain cache state.

For upstream-only.pcap identify the resolver and upstream server. The client-facing query is absent, so the requesting workstation is unresolved. For no-dns.pcap report only that no DNS packet appears in this file. A Wireshark resolved screen name is not proof of an exchange. Request a prior window, client-facing lookup, or resolver record identifying the client as appropriate.

## Optional offline command checks

Python 3.10+ standard library and Wireshark/TShark are sufficient; no Python packages are required. Commands below were exercised on Ubuntu 24.04 with Python 3 and native TShark 4.4.0. Windows equivalents are instructions only: use `py -3` for Python, and your installed TShark executable path. No Windows or GUI execution is claimed by the CLI receipts.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r practice/dns-pivot/requirements.txt
.venv/bin/python practice/dns-pivot/verify_fixtures.py --plan practice/dns-pivot/fixtures/fixture-plan.json
```

To rebuild safely, use an empty directory (the builder refuses existing outputs):

```sh
.venv/bin/python practice/dns-pivot/build_fixtures.py --plan practice/dns-pivot/fixtures/fixture-plan.json --output-dir rebuilt
.venv/bin/python practice/dns-pivot/verify_fixtures.py --plan practice/dns-pivot/fixtures/fixture-plan.json --capture-dir rebuilt
```

Optional inspection commands, with the fixture path for each file:

```sh
tshark -r practice/dns-pivot/fixtures/client-facing.pcap -Y 'dns.flags.response == 1' -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e dns.id -e dns.qry.name -e dns.resp.name -e dns.a -e dns.aaaa -e dns.resp.ttl
tshark -r practice/dns-pivot/fixtures/client-facing.pcap -q -z conv,tcp
tshark -r practice/dns-pivot/fixtures/upstream-only.pcap -Y 'dns.flags.response == 1' -T fields -e frame.number -e ip.src -e ip.dst -e dns.qry.name
tshark -r practice/dns-pivot/fixtures/no-dns.pcap -Y 'dns' -T fields -e frame.number
python3 practice/dns-pivot/limited_builder.py --spec practice/dns-pivot/limited-fixture-plan.json --output limited-rebuilt.pcap
```

The older limited builder can overwrite its explicitly selected output, so choose a new scratch filename. Compare its SHA-256 with SCHEMA.md before use. The full builder's no-overwrite behavior is separate.

For homework, use one authorized answer in your own offline capture and the blank worksheet. Check each returned address and earlier answer history. Supply your own file and frame citations. If neither client-side lookup nor later client traffic is visible, report both gaps and request specific missing evidence. No learner homework has been performed by this lab.
