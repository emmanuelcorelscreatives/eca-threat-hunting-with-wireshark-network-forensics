import csv,json,subprocess,pathlib,sys,hashlib
r=pathlib.Path(__file__).parent;rows=list(csv.DictReader((r/'case-manifest.csv').open()));results=[]
mode=sys.argv[1] if len(sys.argv)>1 else 'training'
if mode not in ['training','all']:raise SystemExit('Use training or all')
for x in rows:
 if mode=='training' and x['partition']=='holdout':continue
 cap=r/('synthetic-authorized-baseline.pcap' if x['partition']=='baseline' else 'synthetic-labelled-cases.pcap');expr=f"ip.src == {x['source_ip']} && ip.dst == {x['destination_ip']} && udp.dstport == 9999 && frame.time_epoch >= {x['window_start_epoch']} && frame.time_epoch < {int(x['window_start_epoch'])+60}"
 cmd=['tshark','-n','-r',str(cap),'-Y',expr,'-T','fields','-e','frame.number','-e','frame.time_epoch','-e','ip.src','-e','udp.dstport'];p=subprocess.run(cmd,capture_output=True,text=True,check=True);events=len(p.stdout.splitlines());assert events==int(x['expected_events']),(x,events)
 results.append(dict(case_id=x['case_id'],command=cmd,stdout=p.stdout,events=events,observable=x['observable']=='true',partition=x['partition'],label=x['label'],asset_role=x['asset_role']))
print(json.dumps({'state':'PASS','measurement':'UDP datagrams, same 60-second UTC window, source to 198.51.100.10:9999; no connection count inference','cases':results},indent=2))
