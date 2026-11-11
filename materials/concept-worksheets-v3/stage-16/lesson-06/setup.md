# Setup and blank register schema

Downloadable draft contents supplied here: `worksheet.md`, `answer-guide.md` and `setup.md`; no repository publication is implied. Use the blank worksheet in LibreOffice Writer 24.2 on Ubuntu 24.04 with its English light interface. If authorized case evidence becomes available, examine a working copy in Wireshark 4.4.9 on the same workstation and cite the original. No C2 case capture or host excerpt is bundled.

Optional DNS-only citation practice is available in the verified public repository `https://github.com/emmanuelcorelscreatives/eca-threat-hunting-with-wireshark-network-forensics`: `practice/dns-baseline/README.md` and its six-packet synthetic DNS fixture. It establishes neither compromise nor a later connection.

For the planned blank `c2-evidence-register.csv`, save this header as a CSV with **no data rows**:

```csv
source_id,source_kind,observation_point,coverage_start,coverage_end,time_basis,clock_difference,address_mapping,missed_direction_or_period,event_time,display_time,reference,src_endpoint,dst_endpoint,protocol,dns_name,dns_response,application_field,process,observation,interpretation,uncertainty
```

**Schema:** `source_id` identifies the original capture or supplied host record. `source_kind`, observation point, coverage bounds, time basis, clock difference, mapping and missed direction/period describe source limits. `event_time` retains its basis; `display_time` records the view used. `reference` holds the original frame or host-record reference. Endpoints include ports where visible. DNS, application and process fields contain only observed values. Keep observation distinct from interpretation and uncertainty. Zero rows do not establish inactivity. The planned ODT and CSV are not claimed to exist.