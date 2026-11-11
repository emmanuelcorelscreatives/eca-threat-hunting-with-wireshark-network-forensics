# Answer Guide — Conceptual Criteria

**Purpose:** Reasoning criteria only. No case findings or observed results are supplied.

## Situation 1

**Expected entry:** Hypothesis-first.

A valid question template is: Did `[reported workstation]` make `[described outbound contact]` during `[available authorized window]`? Keep identifiers unknown unless supplied. Check approved updates, known services, and whether the capture could see outbound traffic. Missing direction or time coverage leaves the question unresolved.

## Situation 2

**Expected entry:** Baseline-first.

Align workstation role, capture point, traffic directions, time windows, and schedule. Then ask whether the peer relationship differs and what changed operationally. Correct unequal coverage before judging rarity. A difference raises a question; it is not a maliciousness verdict.

## Situation 3

**Expected entry:** Intelligence-led.

Check the notice's origin, currency, relevance, and candidate peer before searching. A valid question is: Did an in-scope host contact `[candidate peer]` during covered time? A match would establish contact within scope, not motive, process, approval, or compromise. Shared or reassigned addressing and routine activity remain alternatives.

## Outcome reasoning

- **Match:** Describe only the visible endpoints, timing, direction, and protocol details within coverage.
- **Scoped non-match:** State only that no match was found in adequately covered traffic; do not generalize beyond it.
- **Missing coverage:** Mark the question unresolved and request the appropriate source.

Widen only for a specific unexplained observation. Examine related contact over a limited authorized period; consider comparable devices only if the first comparison still raises a question.

## Checkable expected result

Each situation should include all of these:

- the expected entry point;
- one observable, non-assumptive question;
- unsupplied values marked unknown;
- capture-point, time, and direction limits;
- an ordinary alternative and a way to check it;
- bounded match, non-match, and missing-coverage claims;
- a specific widening condition.

The reflection must separate observation, explanation, and further evidence. Invented peers, addresses, packets, frames, counts, processes, approvals, or compromise claims do not meet the criteria.