# Answer Guide — Credential-Risk Escalation

## Checkable no-case result

A correct submission has all of the following:

- The decision question is neutral: determine whether authentication activity, if established, warrants a credential-misuse investigation or could reflect an approved service or outdated credential. It does not announce an attack.
- Requested interim action: ask the identity-system owner to check retention now and preserve relevant records once scope permits; investigate assets or accounts only if subsequent evidence identifies them. Do not imply that any activity, asset, or account has been identified.
- Every capture-scope field is `unresolved`. No window, time zone, identifier, collection point, clock condition, gap, or copy status is invented.
- Expected evidence-row totals are packet **0**, asset **0**, and identity **0**.
- All five account questions are `unresolved` or impossible to classify. No account-to-host link or authentication outcome is asserted.
- Credential misuse, outdated service credentials, and approved maintenance remain open. `Inconclusive pending identity and service context` is acceptable only if it does not imply that traffic was observed.
- Captured traffic is not established; the initiator, process, account use, authorization, and compromise status remain unresolved. No unsupported high-risk label is used.
- Limitations treat clock and address-mapping uncertainty and possible traffic-direction or collection gaps as unresolved, not observed defects; `kerberos || ntlmssp || ldap` misses authentication traffic decoded as other protocols, and no display filter can recover uncaptured traffic or establish identity.
- Urgency is conditional on verified asset sensitivity, observations, retention, and evidence-loss risk.

## Expected requests and reasoning

1. **Identity-system owner:** check retention now; preserve and provide individual failed and successful authentication records, credential checks, and destination-host logons for the bounded window once established. Request records, not totals.
2. **Capture or case owner:** provide the original capture identifier, collection point, covered period, timestamp basis, gaps, clock assessment, and copy history.
3. **Endpoint or service owner:** identify the initiating process and evidence of retries, a credential change, or a scheduled job.
4. **Operations owner:** provide the approved maintenance record for the window.
5. **Address-assignment owner:** provide the period-valid assignment before an address is named as an asset.

The decision owner must be identified by the organization or marked `unresolved` with a request to designate one; do not invent a person.

Packets can locate exchanges, mappings can identify devices for a period, and identity records can address account activity. None substitutes for another. Even a successful logon would not by itself prove authorization, password theft, pass-the-hash, or takeover. The submission passes only if the empty evidence tables, unresolved facts, competing explanations, limitations, and owned requests are all present.