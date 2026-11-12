# Actual native GUI worked reference

These are actual screenshots from an isolated Xvfb session of native Linux Qt Wireshark 4.4.0 on Ubuntu 24.04.5 LTS, with the process environment `TZ=UTC`. They are supplemental kit evidence, not Windows execution or project-video visual approval. They show the exact `lab-reference.pcapng` bytes; the file's SHA-256 is `2ac1a118da3e9c38d469fa0d048de889158dddf120804b539a00035f74cce9a3`. The original shared source and converted file were preserved. No live capture was started.

- `native-01-unfiltered.png`: six visible synthetic DNS frames in the absolute date/time view.
- `native-02-filter-excludes.png`: accepted `frame.number == 999999` display filter and empty packet list.
- `native-03-properties-filtered.png`: actual Properties, six captured, Displayed packet cell dash and zero displayed bytes; same full-file SHA. First/last visible whole-second times are 2026-11-11 00:00:00 and 00:01:00; captured span is 60.020 seconds. Native length795 differs from filesystem/capinfos828 and packet bytes524. This is an observed build-specific summary difference, not an invented explanation.
- `native-05-time-format-menu.png`: actual checked Date and Time of Day radio option. UTC here follows the process time-zone receipt, not an inference that the separate UTC menu item is selected.
- `native-08-name-resolution-state.png`: Resolve network (IP) addresses unchecked. Other resolution options are distinct.
- `native-10-profile-created.png`: Lab Baseline created by copying current settings in the native Configuration Profiles dialog.
- `native-11-profile-active.png`: reopened dialog and actual active Lab Baseline status, with empty Auto Switch Filter cells. This does not prove unrelated automatic rules cannot exist elsewhere.
- `native-13-ipv4-endpoints.png`: actual selected IPv4 tab, two numeric endpoint rows, Limit to display filter unchecked, six packets attributed to each endpoint. These per-endpoint packet counts include both transmitted and received packets; they do not imply twelve unique capture frames.
- `native-15-reopened-reference.png`: file reopened through native File > Open after selecting Lab Baseline; six frames restored, clear display filter, active profile.
- `native-16b-profile-saved-resolution.png`: reopened Preferences under Lab Baseline, Resolve network (IP) addresses still unchecked.
- `native-17-profile-saved-time-menu.png`: after reopening, actual checked Date and Time of Day radio option with Lab Baseline active.

`native-execution.json` preserves exact screenshot hashes, window titles, action records, OS identity, time-zone environment, source hashes and saved profile settings. Action requests alone are not proof of a visible result; use each screenshot's limited role. The independent per-image verdicts and their receipt hashes are in `native-independent-approvals.json`. The full kit receives a separate content review after every member is finalized.
