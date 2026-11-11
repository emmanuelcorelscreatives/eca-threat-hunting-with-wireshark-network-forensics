# Setup — Supplemental Synthetic Practice

> A packet capture can answer your question and expose someone’s password in one click.

## Scope

This pack supplements the saved no-file demonstration. It is a manually authored **SYNTHETIC EXERCISE**, not a capture, incident record, unchanged evidence, or Wireshark output. No case packets or companion files are supplied. The fictional recipient needs only the relationship between an authorization-bearing request and its response.

These draft materials require separate review and do not constitute visual approval. Approved destination after review—not a publication claim: `materials/stage-3/lesson-5/` in the [verified course repository](https://github.com/emmanuelcorelscreatives/eca-threat-hunting-with-wireshark-network-forensics).

## Requirements and loading

Required: authorized isolated practice directory, UTF-8 Markdown viewer, and no production captures, credentials, or decryption material. Python 3 is only for later repository validation.

1. Save `setup.md`, `worksheet.md`, and `answer-guide.md` together.
2. Read the fixture, then complete the worksheet without transcribing marker text.
3. Consult the answer guide afterward. Wireshark is not required; do not create a capture.

## Synthetic candidate recipient view

```text
SYNTHETIC TEACHING FIXTURE — NOT CAPTURE EVIDENCE
list_summary: authorization field present
details.basic_authorization: [DEMO_ONLY_BASIC_MARKER_NOT_A_CREDENTIAL]
bytes.basic_authorization_text: [DEMO_ONLY_BASIC_MARKER_NOT_A_CREDENTIAL]
details.session_identifier: [DEMO_ONLY_SESSION_MARKER_NOT_USABLE]
bytes.identifying_name: [DEMO_ONLY_FICTIONAL_NAME_MARKER]
relationship: authorization-bearing request followed by response
companion.tls_key_material_marker: [DEMO_ONLY_KEY_MARKER_NOT_USABLE]
```

All bracketed markers are artificial and unusable.

## Data dictionary

| Field | Displayed location | Category | Expected handling |
|---|---|---|---|
| `list_summary` | Packet-list analogue | Likely match | Locate; inspect deeper |
| `details.basic_authorization` | Details analogue | Credential | Restrict; replace or omit |
| `bytes.basic_authorization_text` | Bytes analogue | Retained credential text | Review bytes; replace or omit |
| `details.session_identifier` | Details analogue | Session identifier | Restrict; replace or omit |
| `bytes.identifying_name` | Bytes analogue | Personal identifier | Restrict; replace or omit |
| `relationship` | Teaching text | Needed relationship | May retain |
| `companion.tls_key_material_marker` | Companion-material analogue | Key material | Restrict separately; omit |

Pre-use control: confirm the pack has three Markdown files, an unmistakable synthetic label, and no capture. Expected result: all conditions are true. This is a check specification, not an execution claim.