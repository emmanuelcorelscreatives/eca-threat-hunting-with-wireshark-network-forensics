# Answer guide — verified synthetic fixture

Actual native TShark and the independent PCAP parser agree: primary 98 frames, 42 SMB2 frames overall; source .110 has 36 SMB2 frames, six TCP connections and four distinct peers. The separate backup source .130 adds six SMB2 frames and one peer of its own. Baseline has 14 frames and six SMB2 frames, one .110→.120 connection. Every flow supplies a full TCP handshake, three SMB2 request/response pairs and orderly FIN exchange. Commands are Negotiate (0), Session Setup (1) and Tree Connect (3), with response status 0x00000000. These generated statuses are not product behavior or authentication evidence.

| .110 peer | First decoded SMB2 UTC on 2025-01-16 | SMB2 frame | Earlier SYN/SYN-ACK/ACK | Tree request/success response | Reconnection first SMB2 frames |
|---|---|---|---|---|---|
|192.0.2.120|09:00:20.000|4|1,2,3|8,9|46 at09:02:15;60 at09:02:25|
|192.0.2.121|09:01:20.000|18|15,16,17|22,23|none|
|192.0.2.122|09:03:35.000|74|71,72,73|78,79|none|
|192.0.2.123|09:04:20.000|88|85,86,87|92,93|none|

Frame8 decodes the synthetic share `\\192.0.2.120\AcademyLab`. The other connections use AcademyLab on their own respective peers. Frame32 is first SMB2 for the separate .130→.140 backup pair at09:01:40, with SYN29. Each first SMB2 follows its own SYN by100ms; clearing the SMB filter reveals the earlier attempt. First observed real-world order remains uncertain across declared gap and outside the sparse recorded intervals.

UTC minute bins have new/cumulative/repeats/SMB2-frames: 09:00=1/1/0/6;09:01=1/2/0/6;09:02=0/2/2/12;09:03=1/3/0/6;09:04=1/4/0/6. The third minute's packet peak adds zero new peers. Gap overlaps 09:02 and09:03 bins. The actual CLI relative-time graph starts at09:00:19.900, producing6,12,6,6,6; record the chosen origin before comparing. The primary running distinct count is1→2→2→3→4. Baseline one peer at firstSMB2 frame4 (2025-01-15 09:00:20), TCP frames1–3 and Tree Connect8/9; its observed duration0.300s cannot validate a five-minute comparison window.

D-100 lists .120 and .121, actual09:00:10–09:01:55. Their first exchanges fit those records and strengthen a routine deployment explanation without proving the job caused them. The repeat .120 connections at09:02:15 and09:02:25 are20 and30seconds AFTER actual finish; the planned09:05 end and target-list membership do not explain that timing. Request accurate run/retry history, host process records and measured clock checks. .122 and .123 are unlisted targets; ask their owner and request approved scope. B-200 source .130 and target .140, actual09:01:35–09:01:55, align with its separate09:01:40 exchange; that does not explain .110 traffic. Backup naming alone explains nothing else.

Supported: this synthetic capture shows .110 communicating bidirectionally with four observed SMB2 peers and reconnecting twice to .120. Possible explanation: some first listed contacts align with the synthetic deployment record. Unresolved: post-run repeats, unlisted peers, full contact order and baseline comparability. Request host/job evidence and coverage. No operator, permission, real file operation, vulnerability or lateral movement is established. Passing an exercise means a bounded reasoned comparison, not an accusation.
