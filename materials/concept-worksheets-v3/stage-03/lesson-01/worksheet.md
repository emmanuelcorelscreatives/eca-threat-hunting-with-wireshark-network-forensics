# Inspection Worksheet

Use one authorized offline capture. Enter exact observed values or **not available**; do not infer values from the filename or surrounding traffic.

## 1. Input and handling record

| Item | Entry |
|---|---|
| Capture reference | ______________________________ |
| Expected event start and end | ______________________________ |
| Collector-stated scope | ______________________________ |
| Collector-stated capture point | ______________________________ |
| Other supplied context | ______________________________ |

- [ ] Display-filter bar remained empty.
- [ ] No conversation or payload was inspected.
- [ ] No comments or other changes were saved to the original.

## 2. File-level observations

| Field | What it represents | Exact observation |
|---|---|---|
| Format | Tool-identified capture-file type, not filename extension | __________________ |
| File size | Saved size on disk, not application payload volume | __________________ |
| Encapsulation | Recorded link-layer representation, not physical location | __________________ |
| First packet timestamp | Exact reported value | __________________ |
| Last packet timestamp | Exact reported value | __________________ |
| Duration | Reported earliest-to-latest packet-time difference | __________________ |
| Interface name/description | Exact text, or **not available** | __________________ |
| Other interface/environment details | Exact text, or **not available** | __________________ |

## 3. Tool comparison

| Field | Capture File Properties | `capinfos` | Same, different, or unavailable? |
|---|---|---|---|
| Format | __________ | __________ | __________ |
| Disk size | __________ | __________ | __________ |
| Duration | __________ | __________ | __________ |
| Encapsulation | __________ | __________ | __________ |
| Interface details | __________ | __________ | __________ |

If values differ, what requires investigation?

____________________________________________________________________

## 4. Support assessment

1. Time relationship: [ ] outside [ ] overlaps [ ] cannot classify

Reason using the reported span and expected event window:

____________________________________________________________________

2. Separate the evidence categories:

| Category | Notes |
|---|---|
| What the file actually records | ______________________________ |
| What its format could hold but does not show here | ______________________________ |
| What only collector context can establish | ______________________________ |

3. What might this file support?

____________________________________________________________________

4. What remains unknown?

____________________________________________________________________

5. One next question for the collector:

____________________________________________________________________

**Optional synthetic exercise:** Repeat only these mechanics with the verified DNS supplement and label every observation **supplemental synthetic practice**, not an incident finding.