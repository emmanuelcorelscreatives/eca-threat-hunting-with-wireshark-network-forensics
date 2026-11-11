# Setup and scope

**Status:** Draft supporting artifact. This activity is explicitly synthetic; it is not a packet capture, captured incident, or observed result.

## Downloadable resources

- `setup.md`: scope, fixture rules, and loading instructions.
- `worksheet.md`: complete synthetic ledger, data dictionary, and blank work areas.
- `answer-guide.md`: source-derived checks and explanatory reasoning.

All required exercise input is embedded in `worksheet.md`. No capture, addresses, credentials, decryption material, Wireshark installation, or DNS fixture is required. The published DNS baseline is excluded because it supplies no TCP-transfer evidence here.

## Prerequisites and loading

Use any text or Markdown reader. The approved shared environment is Python 3.11 or later with the standard library only, but this manual activity does not require Python or an external checker. Open `worksheet.md`; treat every range as inclusive and process A, B, then C.

## Calculation rules

1. Stay within the stated single TCP connection and source-to-peer direction.
2. Transmitted TCP payload equals the sum of `tcp.len`.
3. Distinct observed transport positions equal the size of the union of inclusive ranges. Range size is `last - first + 1`.
4. Do not infer absent frame lengths or application content.

No command execution, repository placement, or case finding is claimed.