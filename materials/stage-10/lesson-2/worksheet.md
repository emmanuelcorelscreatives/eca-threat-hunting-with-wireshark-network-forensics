# Investigation worksheet

1. Record filename, SHA-256, capture point description, client, UTC window and unavailable telemetry. State the narrow hypothesis before filtering.
2. Inventory all HTTP requests. For each, record timestamp, frame, stream, source/destination, method, Host and path. Explain why the first visible request does not establish the user's original lure channel.
3. Pair all eight requests with responses. Use packet conversation and available HTTP links; flag any absent automatic link. Record status, Location and source frame. Explain why 304 is not a navigation hop.
4. Resolve `/step` using the first request URL. For every proposed target, search all later client requests across streams. Mark observed follow-up or unresolved. Draw a solid evidence link only for a matching later host/path request; leave proposals without one dashed. A temporal match supports observed follow-up, not proof of browser causality.
5. Check the text response and the 206 response. Compare content length, captured payload and Content-Range with the claimed object length. Explain the difference between a complete HTTP response body and a complete original object. Check truncation, sequence gaps and decoder limits before making a delivery claim.
6. Compare the updater-design control with the first sequence. Record which context comes from scenario design and which facts are packet-derived. Could ordinary browsing fit? Do not infer maliciousness from host count.
7. Write a short assessment: observed chain, unresolved proposal, benign alternatives, confidence and gaps. Leave preceding user action, local storage, execution and compromise unknown. Request browser history and file/process telemetry if those questions matter. Prepare the next lesson by noting content types without extending into detailed form/header analysis.

Fill redirect-chain-worksheet.csv with one row per request/response pair; add limitations to every inference. Include both time and frame/stream references so another analyst can reproduce the work.
