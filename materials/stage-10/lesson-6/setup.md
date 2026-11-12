# Setup and safe use

Extract the complete kit into a writable local directory. Open a terminal in that directory. Use an authorized training machine. The supplied captures contain only loopback lab traffic. Do not collect production traffic or supply production credentials or keys.

Required for read-only checks: Python 3.10+ standard library and TShark. For GUI work install Wireshark. The local collection used Linux, Python/OpenSSL TLS 1.3, tcpdump and TShark. There are no pip dependencies. Check available versions with `python3 --version`, `tshark --version`, and `wireshark --version`.

Validate supplied captures:

```sh
python3 check_fixture.py --root captures
```

To save a new report, choose a path that does not already exist:

```sh
python3 check_fixture.py --root captures --write-results my-results.json
```

Open `captures/candidate.pcap` in Wireshark. The server uses TCP 18443; the updater uses 18444. These are high local ports, not conventional 443. If TLS is not recognized, select a TCP packet, use Analyze → Decode As, choose the server TCP port, select TLS, and apply. Repeat with 18444 in the updater file. CLI checks explicitly use `-d tcp.port==18443,tls` or `-d tcp.port==18444,tls`. Never treat a recognition problem as an absence of encrypted activity.

Optional fresh collection, on a Linux host you own, using tcpdump capture privilege:

```sh
sudo python3 build_fixture.py --output fresh-captures
python3 check_fixture.py --root fresh-captures --write-results fresh-results.json
```

The output directory must be absent; the builder fails if it exists. It binds only 127.0.0.1, generates a temporary self-signed certificate, disables certificate verification only in this disposable local client, sends inert data, and publishes no keys. It does not change routes, create namespaces or contact an external address. Ports 18443/18444 must be free; port collisions fail. Temporary certificate/key files are removed on normal exit. The traffic client receives bytes in memory and does not save an object. If collection fails, keep the partial directory for diagnosis and use a different output path after addressing the error. The supplied captures need no sudo.

This is a deliberate implementation refinement from the earlier proposed namespace draft: loopback avoids network configuration changes. Both endpoints have the same IP; direction must be identified by TCP ports. Do not generalize this topology to an endpoint/gateway case. No DNS is collected; SNI names are passed directly to TLS and require no resolver.
