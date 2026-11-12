#!/usr/bin/env python3
"""Read-only exact capture validation; optional results output refuses overwrite."""
import argparse,csv,datetime,hashlib,io,json,pathlib,subprocess
p=argparse.ArgumentParser();p.add_argument('--root',default='captures');p.add_argument('--write-results');a=p.parse_args();root=pathlib.Path(a.root);m=json.loads((root/'fixture.json').read_text());assert m['synthetic'] is True
results=[]
for s in m['scenarios']:
 f=root/s['file'];fields=['frame.number','frame.time_epoch','ip.src','ip.dst','tcp.srcport','tcp.dstport','frame.len','tls.handshake.type','tls.handshake.extensions_server_name','tls.handshake.extensions.supported_version','tls.record.content_type','tls.record.opaque_type']
 cmd=['tshark','-n','-r',str(f),'-d','tcp.port=='+str(s['port'])+',tls','-T','fields','-E','separator=,','-E','quote=d','-E','header=y']
 for v in fields:cmd+=['-e',v]
 q=subprocess.run(cmd,capture_output=True,text=True,check=True);rows=list(csv.DictReader(io.StringIO(q.stdout)));assert rows,'empty capture'
 assert all(r['ip.src']=='127.0.0.1' and r['ip.dst']=='127.0.0.1' for r in rows)
 hello=[r for r in rows if '1' in r['tls.handshake.type'].split(',')];assert len(hello)==1 and hello[0]['tls.handshake.extensions_server_name']==s['sni']
 assert any('0x0304' in r['tls.handshake.extensions.supported_version'] for r in rows),'no TLS1.3 negotiation'
 assert s['receipt']['negotiated_tls']=='TLSv1.3' and s['receipt']['client_saved_object'] is False
 assert float(hello[0]['frame.time_epoch'])>datetime.datetime.fromisoformat(s['simulated_report_anchor_utc']).timestamp()
 app=[r for r in rows if '23' in (r['tls.record.content_type']+','+r['tls.record.opaque_type']).split(',')];assert app,'no encrypted records'
 directions={}
 for label,key in [('peer_to_client','tcp.srcport'),('client_to_peer','tcp.dstport')]:directions[label]=sum(int(r['frame.len']) for r in rows if r[key]==str(s['port']))
 conv=subprocess.run(['tshark','-n','-r',str(f),'-q','-z','conv,tcp'],capture_output=True,text=True,check=True)
 results.append({'file':s['file'],'sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'bytes':f.stat().st_size,'frames':len(rows),'first_epoch':rows[0]['frame.time_epoch'],'last_epoch':rows[-1]['frame.time_epoch'],'duration_seconds':float(rows[-1]['frame.time_epoch'])-float(rows[0]['frame.time_epoch']),'client_hello_frame':int(hello[0]['frame.number']),'client_hello_epoch':hello[0]['frame.time_epoch'],'visible_sni':s['sni'],'encrypted_record_frames':[int(r['frame.number']) for r in app],'frame_length_totals_whole_capture':directions,'scope':'Whole supplied capture, includes headers and handshake; directions defined by server TCP port because both endpoints use loopback','decoded_fields_csv':q.stdout,'tshark_conversations':conv.stdout,'actual_commands':[cmd,['tshark','-n','-r',str(f),'-q','-z','conv,tcp']]})
events=[json.loads(l) for l in (root/'endpoint.jsonl').read_text().splitlines()];assert all(e['synthetic'] and e['host_id']==m['host_id'] for e in events);assert not any(e.get('linked_artifact_id')=='mock-artifact-A' for e in events)
r={'state':'PASS','checker':'Actual read-only TShark validation, not a GUI approval','captures':results,'endpoint_conclusion':'Mock excerpt supplies no candidate-artifact process link; execution remains unconfirmed and cannot be excluded','gui_executed_by_checker':False}
if a.write_results:
 with open(a.write_results,'x') as f:json.dump(r,f,indent=2);f.write('\n')
print(json.dumps(r,indent=2))
