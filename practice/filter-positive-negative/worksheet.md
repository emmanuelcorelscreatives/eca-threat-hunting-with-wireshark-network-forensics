# Blank filter notebook

Capture file: ____  Authorized scope/host: ____  Observation point: ____  Time window: ____  Known collection or decoding gaps: ____

**Hypothesis:** The expression selects the packets needed for the stated question, rather than merely passing syntax validation. Write predictions *before* applying a filter. P01–P07 are synthetic case IDs, **not frame numbers**; consult the checked mapping only after making predictions. In a different authorized capture, find your own controls. Enter a source file and actual frame only after inspecting the unfiltered file. Mark absent controls **untested**.

## 1. Decoded IPv4 involving the host, both directions

Intent and time scope: ____  Candidate exactly as tested: `ip.src == 192.0.2.10`  Prediction: host-source packets may remain; peer replies may disappear. Corrected expression exactly as tested: `ip.addr == 192.0.2.10`. Predict outgoing and incoming separately. The candidate fails this intent if a known reply is hidden.

| Needed comparison | Synthetic control | Actual unfiltered file / frame | Candidate visible? | Corrected visible? |
|---|---|---|---|---|
| Host-source IPv4 | P01 or P03 | ____ / ____ | ____ | ____ |
| IPv4 sent to host | P02 or P04 | ____ / ____ | ____ | ____ |
| Unrelated IPv4 | P05 or P06 | ____ / ____ | ____ | ____ |

Unfiltered total: ____  Candidate displayed: ____  Corrected displayed: ____  Clear and reapply: relevant packet still visible? ____; unrelated packet hidden? ____. The count difference measures hidden packets, not their importance. Missing reverse-direction control: ____  Possible approved application/asset context to check: ____  Limits: ____  Outcome and reason (validated for stated selection scope / failed by control / inconclusive): ____

## 2. Decoded IPv4 TCP involving the host

Intent and time scope: ____  Expression exactly as tested: `tcp && ip.addr == 192.0.2.10`. This cannot answer entry 1’s all-protocol question.

| Comparison | Synthetic control | Actual unfiltered file / frame | Visible after filter? |
|---|---|---|---|
| TCP from host | P01 | ____ / ____ | ____ |
| TCP to host | P02 | ____ / ____ | ____ |
| UDP involving host | P03 or P04 | ____ / ____ | ____ |
| Unrelated TCP | P05 | ____ / ____ | ____ |

Unfiltered total: ____  Displayed: ____  Missing controls: ____  Harmless-match explanation and context check: ____  Limits: ____  Outcome and reason: ____

## 3. Challenge a negative source test

Define intended matches first: ____  Predict separately for a host transmission, peer reply, and frame without `ip.src`. Compare the **exact** expressions `ip.src!= 192.0.2.10` and `not (ip.src == 192.0.2.10)`; neither excludes every packet involving the host.

| Comparison | Synthetic control | Actual unfiltered file / frame | `!=` visible? | `not` visible? |
|---|---|---|---|---|
| Source is host | P01 or P03 | ____ / ____ | ____ | ____ |
| Peer reply to host | P02 or P04 | ____ / ____ | ____ | ____ |
| No IPv4 source field | P07 ARP control | ____ / ____ | ____ | ____ |

Unfiltered total: ____  Displayed for each expression: ____ / ____  Non-IP check untested if no same-file frame exists: ____  Field/capture limits: ____  Outcome and reason: ____

For every entry, separate observed selection from inference about legitimacy. If a control contradicts the prediction, revise the goal or expression and retest. If the capture lacks a control, seek a better labelled comparison capture rather than claiming success. Keep this notebook for the next lesson’s conversation analysis.
