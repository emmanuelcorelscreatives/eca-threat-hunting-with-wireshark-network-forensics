# Worksheet: Which Gate Explains an Empty View?

Work from the lesson’s stated rules. `tcp` and `udp` are filter text, not evidence that either kind of traffic occurred. No case file is loaded and no collection is performed. Every labelled synthetic exercise is conditional, not an observed incident or result.

## Reference

A capture filter acts before packets are written and decides what enters the saved file. A display filter acts on already-saved packets and changes the current view, not the file. Collection scope includes the approved observation point and time window; an acquisition record documents collection settings.

## Questions

1. Source cue: **Enter tcp in that capture-filter control, without starting collection.** Where is this control, when would the rule act, and does entering the text start a capture?

**Answer:**  
____________________________________________________________

2. **Synthetic exercise 1:** Suppose ordinary UDP reached the chosen interface during a future window while the capture filter was `tcp`. Would it be saved? What could this establish about a particular case?

**Answer:**  
____________________________________________________________

3. **Synthetic exercise 2:** Where is `tcp` entered as a display filter? If a loaded file contained UDP, what could `tcp` hide and clearing the filter reveal? Would either action alter the file?

**Answer:**  
____________________________________________________________

4. **No case file is loaded in this walkthrough, so the empty list says nothing about network activity.** Explain why an empty screen is not evidence of an empty network.

**Answer:**  
____________________________________________________________

5. **Synthetic exercise 3:** Apply display filter `udp` to a file documented as collected with capture filter `tcp`; there are no matches.

> If it was collected with the tcp capture filter, you’d expect no matches.

State the limited file-level interpretation, the network-level conclusion you must not make, and what to check if the capture rule is unknown.

**Answer:**  
____________________________________________________________

6. In a loaded capture, what can file and displayed-packet counts describe? What can they not count?

> Never treat a displayed count as a count for the whole network.

**Answer:**  
____________________________________________________________

7. Complete this blank evidence note without invented values. Use `unknown` or `not examined` where required.

- Observation point: ____________________
- Time window: _________________________
- Capture filter: _______________________
- Available file: _______________________
- Display filter tried: _________________
- Observed result: ______________________
- Limitation: ___________________________
- Next action: __________________________

8. **Synthetic exercise 4:** A needed match disappears. List the checks in order and an appropriate next action if no suitable historical capture exists. Can a new capture restore packets excluded earlier?

**Answer:**  
____________________________________________________________