# Synthetic containment decision practice

This newly authored fixture is separate from Project 7 and from any incident narrated in the course. No network traffic is sent. All timestamps, entity labels and frames are fictional teaching data. The PCAP is the actual deterministic output of the supplied offline builder.

The fictional service catalog says SVC-01 may use the peer. This is scenario metadata, not a packet finding. The capture point is a fictional client-facing link. Accounts, processes, compromise, approval, retention deadlines and routes beyond that point are unknown.

## Independently inspectable release observations

Actual local execution used Python 3 and TShark 4.2.2 on Linux; no claim of Windows or Wireshark 4.4 execution is made. The three observed frames contain a TCP SYN, SYN/ACK and ACK between 192.0.2.10:49152 and 198.51.100.20:443, beginning at 2025-01-16 12:00:00 UTC and ending 0.04 seconds later. Each has zero TCP payload. There are no malformed frames. Port 443 alone does not prove TLS, a user, process, compromise or data transfer.

PCAP SHA-256: `ce2ca86ceca419cf6c34ca1186b12da22b3eaff2f339bfd734a339ffedcb196d`.

See tshark-fields.stdout.txt for actual fields and checksum statuses, generation.stdout.txt for the executed generator output, and the builder/spec for reproducibility. Recalculate original and analysis-copy hashes rather than copying a sample value into an evidence ledger.

On Windows use the commands in setup.md. The downloadable PCAP requires no Python installation for student use. These Windows instructions have not been executed here.
