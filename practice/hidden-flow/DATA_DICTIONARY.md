# Data dictionary and trust boundary

Both CSVs are UTF-8, headered, synthetic Academy scenario inputs. They are not packet exports, endpoint logs, proxy logs, or evidence of actual collection. Blank `known_service` or `device_id` means **unknown**, not “none.” All times are UTC; addresses are documentation-only IPv4 ranges.

`fixture-metadata.csv`: `ip` is the proposed mapping address; `device_id` is an authored inventory label; `role` is proposed inventory context; `capture_point` describes a **planned**, unmeasured vantage; `window_start_utc` and `window_end_utc` bound the design; `coverage` explicitly withholds a completeness claim; `known_service` is a hypothetical inventory label, **not** a name extracted from packets.

`scenario-flows.csv`: `scenario_id` identifies a proposed connection; `asset_ip` and `peer_ip` are planned endpoints; `client_port` and `peer_port` are proposed TCP ports; `design_start_utc` and `design_end_utc` are schedule targets, **not observed packet times**; `planned_transport` is an implementation target, not a decoded protocol. Distinct client ports distinguish proposed connections but do not prove that packets exist.

Join the files on `ip = asset_ip` or `ip = peer_ip`. Do not promote a joined inventory label or designed schedule into packet evidence. A completed capture would require its own validated packet-to-claim references.