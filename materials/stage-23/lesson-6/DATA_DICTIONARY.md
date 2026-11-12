# Data dictionary

All IP addresses and the academy.test domain in practice.pcap are synthetic. executed-fixture-spec.json is the exact executed byte design; capture-execution.json records the actual deterministic rebuild and current CLI decode. The capture timestamps are fixed synthetic timestamps, not a real collection window. Historical logs are explicitly historical.

The handoff evidence object separates packet_observation (null until learner inspection), inference, alternative explanations, confidence_limit and unknowns. monitoring contains requests for actual target-source verification; required_fields is illustrative, not a confirmed schema. Accepted owners need role, date and evidence reference. gates and tests distinguish unrun, failed and passed. A passed gate needs a reference; positive expectations must precede an authorized test, although the validator cannot verify chronology. Scheduled activity decisions are not measured false-positive rates.

reviews.owner coordinates the review; reviews.proposal_owner is the recipient responsible for a documented retain/revise/pause decision. trigger_route describes sender, recipient, channel, interval and acknowledgement. notification_ref records actual delivery back to that owner. proposal_owner_decision_ref records the decision. next_date schedules the next review; following_date records the date set by a completed review. Early triggers override cadence. blind_spots have independent priorities, owners, scope/access/effort, acceptance checks and closure evidence.

verify-handoff.py implements the keywords used by the supplied schema and additional policy checks. It is not a general JSON Schema library. It validates references and training state, never operational truth. ISO dates are checked where acceptance or review completion requires them; future dates and agreements require human verification against the actual review time.


## Required handoff detail

Assess whether the responsible owner can inspect source health, coordinate authorized tests, read alerts and approve changes. Record each capability, access limitation and evidence reference in owners.capability_assessment; unknown access remains open even after a role is accepted. Give the reviewer a brief explaining the matched behavior, similar approved activity, evidence that could change the conclusion and an escalation contact; fill monitoring.reviewer_brief without treating a match as compromise.

Explain reviews.timing_rationale using the actual risk and the team's monitoring capacity. Discuss each gap's coverage gain, retention risk, authorized access and effort with responsible teams; in gap_priority_acceptance record who accepted the ordered priorities, when and the acceptance reference. Numeric ranking alone is insufficient.

reviews.decision and reviews.proposal_owner_decision represent the same final documented owner decision and must agree when either indicates completion. Even a proposed handoff needs a named review owner, proposal owner and route before recording a completed review. A proposal may remain proposed after a completed review because operational gates remain unmet. The validator checks basic routing and decision consistency; humans must assess capability evidence, reviewer content, cadence rationale and priority acceptance truth.

