# Setup — Define What Data Loss Would Mean

**Status:** Draft supporting artifact requiring separate course review. This is not visual approval.

## Downloads and prerequisites

Download and keep `setup.md`, `worksheet.md`, and `answer-guide.md` together. The worksheet contains every exercise input. The shared course prerequisite is Python 3.10 or later with the standard library, although this Markdown exercise runs no code. Use an offline text editor or Markdown reader. No network access, Wireshark session, credentials, external dataset, or production data is required.

No case capture is supplied or claimed. The optional verified `practice/dns-baseline` supplement is DNS-only and is not an exercise input; it cannot establish compromise or a later connection.

## Workflow

1. Copy `worksheet.md` to preserve a blank original.
2. Use only the supplied synthetic cards. Do not invent packets, addresses, times, or findings.
3. Complete the worksheet before opening `answer-guide.md`.

## Evidence vocabulary

- **Documented:** Explicitly stated by a supplied card.
- **Interpreted:** A plausible meaning not established as fact.
- **Unresolved:** The necessary source is absent or insufficient.
- **Not established:** Use for an authorization gap; it does not mean unauthorized.

## Response data dictionary

| Field | Meaning |
|---|---|
| Dimension | Asset/contact, peer, channel, sensitivity, or authorization |
| Status | One controlled evidence term above |
| Card | Supporting synthetic card letter |
| Observation | Minimum claim the card supports |
| Limitation | What the card cannot establish |
| Next record | Specific authorized source that could reduce uncertainty |