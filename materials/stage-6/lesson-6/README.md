# Threat Hunting with Wireshark Course — Stage 6, Lesson 6
## Recognize Fragmentation and Offload Artifacts

A broken-looking decode does not establish a broken network. Learn to separate IP fragmentation, shortened capture records, missing TCP bytes, checksum interpretation, and plausible host offload.

### Two distinct sources
- **Recorded lecture:** Emmanuel Corels explains how capture boundaries, direction, collection rules, protocol preferences, and observation point constrain conclusions. Its Windows preference walkthrough is original lecture context, not execution evidence for this kit.
- **Additional offline practice:** `practice.pcap` is the unchanged synthetic baseline. `lesson-6-cases.pcapng` supplies eleven explicitly synthetic cases, independently decoded with Linux TShark 4.4.0. Neither file is the lecture capture, a hardware test, or a measured pre/post-offload pair.

### Route through the lesson
1. Read `setup.md` and follow `setup-guide.md` from the downloaded kit directory.
2. Complete `worksheet.md` before consulting `answer-guide.md`.
3. Use `DATA_DICTIONARY.md` for field meanings and `native-validation.md` for the boundary between author validation and your own observations.
4. Preserve both supplied captures. Save notes and preference comparisons separately.

### Learning outcomes
You will group IPv4 fragments by source, destination, protocol and Identification; compare IPv6 Fragment headers; distinguish absent pieces from shortened records; record checksum and reassembly settings; compare synthetic aggregate and segment views without claiming real offload; and explain why Follow Stream and Expert Information cannot recover missing evidence.

The next lesson, **Establish the Environment and Asset Roles**, places trustworthy observations in operational context.

### Publication note
Proposed public location: `materials/stage-6/lesson-6`. This path is not published yet; the downstream publisher must verify it before release.
