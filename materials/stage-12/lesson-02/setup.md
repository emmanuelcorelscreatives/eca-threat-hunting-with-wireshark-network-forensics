# Supplemental lesson kit

This self-contained, wholly synthetic CSV scenario supports the saved lesson’s evidence-correlation exercise. It is **not a packet capture**, a reconstruction of the unavailable case, or a Wireshark finding. No credentials or real identities are included.

Download and extract the complete offline kit, keeping every file together. The repository destination is `materials/stage-12/lesson-02/`. Read `worksheet.md`, then compare your conclusions with `answer-guide.md`. The four `synthetic_*.csv` files and `DATA_DICTIONARY.md` contain the scenario. `validate_case.py`, `controls.json`, and `validation-execution.json` provide offline integrity checking and its recorded execution. No shared dataset or `practice.pcap` is required for the CSV exercise.

Open the UTF-8 CSVs together in a spreadsheet or text editor. Import comma-separated headers and keep timestamps, addresses, identifiers, and hexadecimal statuses as **text**; preserve empty fields. Use `DATA_DICTIONARY.md` for joins and field meanings. A spreadsheet or UTF-8 text editor is the only required software. Wireshark is needed only to apply the saved investigation method to a separately authorized offline capture; this kit neither requires nor requests one.

For that method, record capture location, time window, observation point, and whether both directions are covered. In Wireshark use File > Open on an authorized working copy. Inspect `kerberos`, the decoded code-24 error field where available, `ldap.resultCode == 49`, and `ntlmssp`; match requests to responses. Use Statistics > Conversations and Statistics > I/O Graphs with equal intervals. Confirm display-filter fields in the installed version. Conversation totals and graph peaks are not login counts. **These actions cannot be performed on the supplied CSVs as packet evidence.**

Run the actual standard-library checker from the extracted kit folder:

```text
python3 validate_case.py --case-dir .
```

Python 3 is required for validation. Expected result: JSON with `verdict: pass`, 13 exchange rows, 7 identity events, 2 change records, 5 mapped addresses, and one modelled resend. The command returns nonzero for malformed or changed input. The recorded execution is included, together with four scratch corruption rejections. These are checks of this synthetic CSV dataset, not packet decoding, real Windows logs, or an actual authentication investigation.

From the repository root the equivalent verified command is:

```text
python3 materials/stage-12/lesson-02/validate_case.py --case-dir materials/stage-12/lesson-02
```

The execution receipt includes this exact command run against an identical scratch repository layout.
