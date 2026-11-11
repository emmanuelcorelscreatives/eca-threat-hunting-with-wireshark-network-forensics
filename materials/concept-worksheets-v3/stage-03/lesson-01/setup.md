# Setup: Metadata-First Offline Inspection

**Status:** Draft supporting artifact requiring separate review.

## Resources and prerequisites

- Downloadable course files: `setup.md`, `worksheet.md`, and `answer-guide.md`.
- Required external input: one authorized offline capture. The course supplies no capture for this saved demonstration, so no measurements or results are predetermined.
- Required context: the expected event window and any collector-supplied scope or capture-point information. Record missing context as **not available**.
- Required software: Wireshark with Capture File Properties and `capinfos` available.
- Optional synthetic practice: the verified public repository contains `practice/dns-baseline/README.md` and its six-packet synthetic DNS fixture. It is supplemental mechanics practice only and does not establish compromise or a later connection.

## Read-only procedure

1. Work only with the authorized file and leave the original unchanged.
2. In Wireshark, choose **File > Open**. Leave the display-filter bar empty; do not follow traffic or interpret packet rows.
3. Open **Statistics > Capture File Properties**. Do not use **Save Comments** or another write action.
4. At a terminal where `capinfos` is available, first check locally installed options:

   `capinfos -h`

5. Replace the placeholder and inspect the authorized file:

   `capinfos -t -s -u -E -I "<authorized-capture-path>"`

6. Keep capital `-I`; lowercase `-i` requests average data rate instead.
7. Compare both tools as views of the same capture, not as independent captures. Record differences for investigation rather than declaring either tool wrong.

No command output or successful execution is asserted in these materials.