# Setup

Use an isolated authorized lab with Python 3, Wireshark 4.4, TShark and capinfos. The delivered PCAP is synthetic and can be inspected offline. Extract the whole kit and open a terminal in its directory; every command below uses that directory. Retain the downloaded files and use copies for answers. Do not capture production traffic for this exercise.

Run:

```sh
python3 --version
wireshark --version
tshark --version
capinfos practice.pcap
tshark -r practice.pcap -Y dns -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e dns.qry.name -e dns.a
python3 offline-builder.py --spec executed-fixture-spec.json --output rebuilt-practice.pcap
python3 -c 'import pathlib; assert pathlib.Path("practice.pcap").read_bytes()==pathlib.Path("rebuilt-practice.pcap").read_bytes()'
cp plan-handoff-template.json learner-handoff.json
python3 verify-handoff.py learner-handoff.json
```

The builder refuses an existing output; choose a new filename or remove only your disposable rebuilt output. The author actually rebuilt the fixture byte for byte and executed the decoder and validator checks recorded in capture-execution.json and validator-execution.json. Historical logs and historical-assembly-manifest.json describe earlier staging and are retained for provenance; current-kit-inventory.json binds the current delivered bytes.

Open practice.pcap in Wireshark, enter `dns`, and inspect query/reply frames 1/2, 3/4 and 5/6. Record filter, selected frame and observed fields yourself. Author CLI checks are not proof you performed the GUI task. No packet file is needed to complete the conceptual handoff; leave packet_observation null if you do not inspect it.

Use the JSON template and worksheet for responsibilities and review routing. Keep status proposed while any operational gate is unmet. Ready-for-approval means a documented proposal ready for an approver; it is never deployment permission. The schema and Python checks cannot authenticate evidence, acceptance, test chronology, people or operational health. A review trigger must reach the proposal owner through a named route and produce a documented retain/revise/pause decision with a next date.


## Required handoff detail

Assess whether the responsible owner can inspect source health, coordinate authorized tests, read alerts and approve changes. Record each capability, access limitation and evidence reference in owners.capability_assessment; unknown access remains open even after a role is accepted. Give the reviewer a brief explaining the matched behavior, similar approved activity, evidence that could change the conclusion and an escalation contact; fill monitoring.reviewer_brief without treating a match as compromise.

Explain reviews.timing_rationale using the actual risk and the team's monitoring capacity. Discuss each gap's coverage gain, retention risk, authorized access and effort with responsible teams; in gap_priority_acceptance record who accepted the ordered priorities, when and the acceptance reference. Numeric ranking alone is insufficient.

reviews.decision and reviews.proposal_owner_decision represent the same final documented owner decision and must agree when either indicates completion. Even a proposed handoff needs a named review owner, proposal owner and route before recording a completed review. A proposal may remain proposed after a completed review because operational gates remain unmet. The validator checks basic routing and decision consistency; humans must assess capability evidence, reviewer content, cadence rationale and priority acceptance truth.

