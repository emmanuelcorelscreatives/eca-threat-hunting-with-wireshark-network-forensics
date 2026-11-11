# Answer Guide: Choose the Next Evidence Collection

**Purpose:** Conditional reasoning key, not case findings or executed results.

## 1. Packet boundary

Every case-value blank should say `unknown—not supplied`. If an authorized capture later exists, first record its source file, relevant frame references and times, peers, observation point, and scope/window; inspect the relevant frames. Check whether a gateway view may show translated addresses or a resolver view may show the lookup server as peer. A display filter changes the view, not the saved capture.

Packets may support peers and timing. They cannot by themselves name the initiating process, person at the keyboard, or protected content.

## 2. Main request

For the synthetic process question, the expected choice is:

- **Question:** Did an unapproved process or an approved updater initiate the hypothetical connection?
- **Owner/source:** Authorized endpoint owner; available process-to-connection history.
- **Scope:** Supplied device and connection identifiers, defined window, and reason. Because none were supplied here, they remain unknown.
- **Owner checks:** Whether auditing covered the device/window, what was retained, overwrite or shutdown risk, timestamp time zone, known clock differences, and preservation options.
- **Handling:** Original records or documented export, source and collector details, unrelated personal activity excluded, and sensitive material access restricted.

Endpoint evidence ranks first because it addresses process ownership directly—not because endpoint must always come first. Preserve another relevant source in parallel only when its overwrite risk warrants it; otherwise its urgency remains unknown. Analysis and preservation order may differ.

## 3. Changed-question key

| Question | Appropriate source/owner | Important limitation |
|---|---|---|
| Account/device use | Identity or authentication owner | An account does not prove which person used it or which process connected |
| Name/requesting host | Client-side or resolver DNS owner | Upstream data may show only the resolver; cache or missing logs means absence is not proof |
| Proxy-forwarded request | Proxy owner | Use only fields actually logged; do not assume URL, user, content, or process |
| Translation attribution | Firewall or network owner | Address/port mappings do not reveal process or encrypted content |
| Beyond capture window | Network flow owner | Peers, ports, times, and byte counts cannot identify files or prove data loss |

A different first source is acceptable when a different decision-changing question and source-specific reasoning are stated.

## 4. Checkable handoff criteria

A complete answer:

- labels the packet premise as hypothetical and invents no case values;
- names the exact question, focused request, and responsible owner;
- asks about coverage, retention, preservation, original timestamps, time zone, and clock difference;
- separates what a source might reveal from what remains unsupported;
- treats nearby times as relevant but not proof of the same action; and
- records provenance, handling, minimization, and access restrictions.