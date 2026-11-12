# Checked answers for this synthetic exercise

These observations concern the supplied synthetic files only. They do not resolve the lecture’s unavailable incident. See actual HTTP fields, verbose decode, export proof, capture info and scenario records. Packet timestamps are authored UTC; no measured cross-source clock offset or attested excerpt completeness is supplied.

The original PCAP has 39 frames from 2025-01-16 12:00:00 through 12:00:01.200000 UTC. The PCAPNG conversion preserves these packets. The mapped synthetic client is 192.0.2.10 (WS-LAB-01).

| Request | Response | Stream | Result |
|---|---|---|---|
| Frame 6, 12:00:00.130000, portal.academy.test/start | Frame 8, .150000 | 0 | 302, Location http://files.academy.test/review.txt; zero-length body |
| Frame 19, 12:00:00.430000, files.academy.test/review.txt | Frame 21, .450000 | 1 | 200, text/plain, declared and exported body 31 bytes |
| Frame 32, 12:00:01.130000, updates.academy.test/updater-note.txt | Frame 34, 1.150000 | 2 | 200, text/plain, declared and exported body 31 bytes |

The redirect and later GET support a visible chain at this authored observation point. They do not show why the first page was opened. Follow HTTP Stream for frame21 exposes the inert review text. Actual TShark exports match each supplied text file byte for byte. http-export-byte-proof.json supplies hashes calculated from those actual exports; inert-artifacts.zip contains the same two files and their actual-file manifest. A complete reconstructed object at this point does not establish global collection completeness or host execution.

EV-01 is an authored file-create event for the mapped review object after its response. Within this scenario, it supports host save through host/time/URL/path/size consistency, not packet evidence alone or a hash match. EV-02 starts less on an unrelated checklist; it does not identify review.txt. Execution of the proposed object remains inconclusive. Because excerpt completeness is not attested, absence of a matching process entry does not prove non-execution. Request bounded process lineage and collection coverage if that link matters.

For the control, frame34 carries updater-note.txt; EV-03 supplies the authored host-save row. CTX-01 labels the updater approved within this scenario; packet shape alone does not establish safety or business approval. EV-04 starts a viewer with the updater note as an argument, not execution of that downloaded text as a program. Apply the same scope and correlation limits to both objects.

A defensible assessment distinguishes delivery at the observed point (high confidence within verified fixture bytes), scenario host save (supported by separate authored event records with stated limitations), and execution of review.txt (inconclusive). Neither delivery nor save establishes compromise. Alternatives include approved update activity and unrelated nearby process events. Request the specific missing process/object identity or coverage evidence; keep any broader incident conclusion unknown.
