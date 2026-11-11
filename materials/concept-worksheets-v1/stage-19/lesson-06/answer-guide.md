# Answer Guide and Reasoning Key

## Part A checks
A defensible response:
- leaves unknown scope fields blank;
- names the exact counter, direction, units, and interval;
- does not relabel directional bytes as unique content;
- links retransmissions, encryption, or missing coverage to the affected claim;
- assesses traffic, volume, content, sensitivity, authorization, storage, and loss separately;
- uses plain-language confidence rather than an unexplained score; and
- requests one source that addresses the stated blocking question.

There are no fixed packet values. Backup, synchronization, or an approved administrative transfer may be a plausible alternative, but a familiar service name does not prove authorization.

## S1 expected reasoning
1. **Observation:** The declared scenario supports an outbound encrypted session.
2. **Volume:** No named counter or value was supplied, so no volume claim is supportable.
3. **Content:** Upload contents are unknown; unreadable content does not mean sensitive data did not move.
4. **Confidence:** Unauthorized sensitive-data loss is inconclusive because content, sensitivity, authorization, and storage lack corroboration. Authorization to capture traffic is not authorization for the transfer.
5. **Request:** A relevant DLP finding is the targeted source for whether classified material was involved.

## S2 expected reasoning
The narrow claim is: “The available portion displays `record_type=customer`.” One visible field does not establish every record, the unseen remainder, total distinct content, sensitivity, authorization, storage, or data loss. Those claims remain unknown or inconclusive. Independent classification is still required.

Correct matching:
- classification → DLP finding;
- transaction/destination context → proxy details;
- object storage → service upload/audit record;
- process that read a file or opened a connection → endpoint activity.

Prefer “the capture shows” for observation and “may represent” for inference. Do not write “the organization lost sensitive records” without separate evidence for content, sensitivity, authorization, and loss.