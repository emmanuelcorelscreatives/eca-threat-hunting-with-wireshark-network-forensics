# Worksheet

Record tool versions, file SHA256, source synthetic status and profile. Hunt question: which captured exchange exposes a requested decoded application name, and which blanks simply reflect field applicability?

1. Configure all seven custom columns from setup.md, retaining the normal contextual columns. Record every spelling and occurrence setting.
2. Select frame8. Compare TCP Stream, HTTP Host and Method with expanded Packet Details. Select frame10 and explain why a response can have blank request fields. Select frame3 and explain its blank TCP Stream versus populated UDP Stream.
3. Select frames1 and2. Compare DNS Question Name and DNS Response Name with the actual question/answer sections. Distinguish decoded DNS names from address resolution performed for display.
4. Select frame19. Expand TLS → Handshake Protocol: Client Hello → Extensions → server_name. Compare the captured server name with the custom column. Explain why ClientHello alone proves neither completed TLS nor identity, legitimacy or maliciousness.
5. Select frame20. Expand DNS → Answers and compare the two answer names. Set DNS Response Name occurrence0,1,2 in turn and record the values. The same name appears twice; add dns.a temporarily using right-click on an A-address field → Apply as Column, then compare occurrence0,1,2 to distinguish the two addresses. Inspect heading/field in Columns preferences. Restore occurrence0. Select frame8 and check the newly added dns.a column again; explain the blank by field applicability, then return to frame20.
6. Apply `http.request` as a deliberate narrow display filter. Record displayed count and visible evidence. Clear it and verify20frames return. Explain how an omitted packet, an inapplicable field, an undecoded field and uncaptured traffic differ. A display filter cannot recover collection omissions.
7. Write one cautious observation, one alternative explanation, a confidence limit and the next authorized check. Keep colors/comments/bookmarks separate from findings. No private/live capture or attribution is required.
