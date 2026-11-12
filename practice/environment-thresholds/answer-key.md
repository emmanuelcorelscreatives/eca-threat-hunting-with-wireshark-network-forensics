# Checked instructor guide — read after freezing

Baseline counts: B01 4, B02 6 workstation datagrams; B03 12, B04 16 backup datagrams. Baseline packet total 38. Labelled capture total 83, 8 declared case windows including T06 with zero supplied packets. These are packet observations, not connection counts. The actual capture times and per-frame decoded fields are in executed-commands.json and actual-verification.json.

| Case | Context | Count | Current >5 | Proposed role boundary |
|---|---|---:|---|---|
| T01 | benign workstation | 6 | flag | no match |
| T02 | suspicious workstation | 9 | flag | flag |
| T03 | benign backup | 16 | flag | no match |
| T04 | suspicious backup | 20 | flag | flag |
| T05 | unresolved workstation | 8 | flag | flag, still unresolved |
| T06 | suspicious label, unobservable | 0 visible | unobservable | unobservable |
| H01 | held-out benign workstation | 7 | flag | no match (equality does not exceed 7) |
| H02 | held-out suspicious backup | 17 | flag | no match: a labelled miss |

The proposed boundary removes two measured training benign matches while retaining both measured suspicious training matches. This tiny selected training comparison is not a production rate. T05 must not be forced into a benign/suspicious score. T06 is a coverage issue; the sensor did not observe it, so the threshold's effectiveness cannot be scored there. H02 exposes a real tradeoff: role-specific raising loses a visible lower-volume suspicious case. Changing the backup threshold after seeing H02 consumes that holdout; obtain a new independent evaluation set afterward.

The frozen illustrative boundaries derive from the baseline ranges (4/6 and 12/16) and training observations, not a universal formula. They remain provisional despite favorable selected training results. Schedule context never proves destination legitimacy, process identity or maliciousness. A tightly approved exception might reduce routine review but may conceal matching abuse; keep its scope, expiry and review owner explicit. Sensor gaps, unobserved directions, seasonal activity, different windows and new software remain limitations. No sensitive-byte-volume inference is possible here.

Reference freeze/holdout receipts contain the exact proposal SHA256 and outcomes. Files are open to inspection; this is an honest sequencing exercise, not access control. Native views show the real default dialogs and graph, while per-case totals come from executed TShark expressions. Use the same role, filter, direction, datagram event definition and 60-second window for a fair comparison. Keep original lecture results blank and obtain real authorized baseline evidence for your own case.
