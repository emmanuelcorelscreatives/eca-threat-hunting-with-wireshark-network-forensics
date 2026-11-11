# Setup — Encrypted Remote-Access Limits

## Required course downloads

- `setup.md`
- `worksheet.md`
- `answer-guide.md` — review after completing the worksheet

No capture, credentials, logs, case file, or DNS fixture is required.

## Safe environment

Use an isolated workstation with Wireshark’s Display Filter bar. Do not start a live capture, load production data, or load any capture.

## Unloaded-filter step

1. Open Wireshark with no capture loaded.
2. Enter `ssh` in the Display Filter bar.
3. Clear it, then enter `rdp`.
4. Record the result on the worksheet.

With no capture loaded, neither step provides a packet finding. This does not show that remote access did or did not occur; no evidence source was loaded. The steps are learner actions, not execution evidence claimed by these materials.

Complete the worksheet using only its fictional intake card. The existing synthetic DNS supplement is not used because it does not establish remote access, maliciousness, or identity.