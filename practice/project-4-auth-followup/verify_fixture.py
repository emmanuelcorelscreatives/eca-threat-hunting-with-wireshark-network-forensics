from pathlib import Path
import argparse,subprocess,csv,json,hashlib,tempfile,sys,datetime
p=argparse.ArgumentParser();p.add_argument('--tshark',default='tshark');a=p.parse_args();r=Path(__file__).parent
readrows=lambda n:list(csv.DictReader((r/n).open()))
def tsh(cap,*args):return subprocess.check_output([a.tshark,'-r',str(r/cap),*args],text=True)
def fields(cap,names):
 cmd=['-T','fields','-E','header=y']
 for name in names:cmd+=['-e',name]
 return list(csv.DictReader(tsh(cap,*cmd).splitlines(),delimiter='\t'))
for cap,specname,count in [('practice.pcap','fixture-spec.json',23),('protocol-examples.pcap','protocol-examples-spec.json',14)]:
 spec=json.loads((r/specname).read_text());assert hashlib.sha256((r/cap).read_bytes()).hexdigest()==spec['captureSha256'];assert len(tsh(cap,'-T','fields','-e','frame.number').splitlines())==count
 assert not tsh(cap,'-Y','_ws.malformed','-T','fields','-e','frame.number').strip()
 assert not tsh(cap,'-o','tcp.check_checksum:TRUE','-o','ip.check_checksum:TRUE','-o','udp.check_checksum:TRUE','-Y','tcp.checksum.status == 0 or ip.checksum.status == 0 or udp.checksum.status == 0','-T','fields','-e','frame.number').strip()
assert tsh('practice.pcap','-Y','kerberos or ntlmssp or ldap','-T','fields','-e','frame.number').splitlines()==['11','12','19','20']
assert tsh('practice.pcap','-Y','ldap.protocolOp == 1','-T','fields','-e','ldap.resultCode').splitlines()==['0','48']
main=fields('practice.pcap',['frame.number','frame.time_epoch','ip.src','ip.dst','tcp.flags','tcp.stream']);idx={int(x['frame.number']):x for x in main};assert len({x['tcp.stream'] for x in main})==5
mapping={x['address']:x['fictional_system'] for x in readrows('address-map.csv')};assert mapping=={'192.0.2.10':'LAB-CLIENT','192.0.2.20':'APP-A','192.0.2.21':'APP-B','192.0.2.30':'APP-C','192.0.2.40':'DC-LAB'}
for d in readrows('discovery-map.csv'):
 refs=[int(x) for x in d['frame_refs'].split(';')];first=idx[refs[0]];assert first['ip.src']==d['source'] and first['ip.dst']==d['attempted_target'] and int(first['tcp.flags'],16)==2
 if d['responding_peer']!='unknown':
  assert len(refs)==3 and idx[refs[1]]['ip.src']==d['responding_peer']==d['attempted_target'] and idx[refs[1]]['ip.dst']==d['source'] and int(idx[refs[1]]['tcp.flags'],16)==18
  assert idx[refs[2]]['ip.src']==d['source'] and idx[refs[2]]['ip.dst']==d['attempted_target'] and int(idx[refs[2]]['tcp.flags'],16)==20
 else:assert refs==[7] and not any(x['ip.src']==d['attempted_target'] for x in main)
parse=lambda s:datetime.datetime.fromisoformat(s).replace(tzinfo=datetime.timezone.utc).timestamp()
coverage={x['source_id']:x for x in readrows('coverage.csv')};pc=coverage['PCAP'];assert all(parse(pc['start_original'])<=float(x['frame.time_epoch'])<=parse(pc['end_original']) for x in main)
pc2=coverage['PROTOCOL_PCAP'];assert 'practice.pcap;' in pc['coverage_limits'] and 'protocol-examples.pcap;' in pc2['coverage_limits'];protocol_times=fields('protocol-examples.pcap',['frame.time_epoch']);assert all(parse(pc2['start_original'])<=float(x['frame.time_epoch'])<=parse(pc2['end_original']) for x in protocol_times)
events=readrows('identity-events.csv');ev={x['record_id']:x for x in events};assert len(ev)==5
for e in events:
 assert e['time_zone']=='UTC';cov=coverage[e['recording_computer']];assert parse(cov['start_original'])<=parse(e['original_time'])<=parse(cov['end_original'])
 if e['source_address']:assert mapping[e['source_address']]=='LAB-CLIENT'
 assert e['account']=='svc-lab' and e['provenance']=='FICTIONAL DESIGNED ROW'
assert [(ev[x]['event_id'],ev[x]['status']) for x in ['EV01','EV02']]==[('4771','0x18'),('4771','0x19')]
assert ev['EV03']['event_id']=='4776' and not ev['EV03']['destination_field'] and ev['EV03']['source_workstation']=='LAB-CLIENT'
assert ev['EV04']['recording_computer']=='APP-B' and ev['EV04']['event_id']=='4625';assert ev['EV05']['recording_computer']=='APP-A' and ev['EV05']['event_id']=='4624'
proto=fields('protocol-examples.pcap',['frame.number','frame.time_epoch','ip.src','ip.dst','kerberos.msg_type','kerberos.error_code','kerberos.CNameString','ntlmssp.messagetype','ntlmssp.auth.username','http.response.code']);pi={int(x['frame.number']):x for x in proto}
for req,res,event,code in [(1,2,'EV01',24),(3,4,'EV02',25)]:
 assert pi[req]['kerberos.msg_type']=='10' and pi[res]['kerberos.msg_type']=='30' and int(pi[res]['kerberos.error_code'])==code
 assert pi[req]['ip.src']==ev[event]['source_address'] and mapping[pi[res]['ip.src']]==ev[event]['recording_computer'] and pi[req]['kerberos.CNameString']==ev[event]['account']
 assert abs(float(pi[res]['frame.time_epoch'])-parse(ev[event]['original_time']))<.000001
assert [pi[n]['ntlmssp.messagetype'] for n in [8,9,10]]==['0x00000001','0x00000002','0x00000003'];assert pi[10]['ntlmssp.auth.username']==ev['EV04']['account'] and mapping[pi[10]['ip.dst']]==ev['EV04']['recording_computer'];assert pi[11]['http.response.code']=='401'
assert 'LM/NT credential response' in (r/'protocol-examples-guide.md').read_text()
# Completed artifacts follow worksheet schemas and preserve actual source reference/time values.
assert next(csv.reader((r/'worked-timeline.csv').open()))==next(csv.reader((r/'timeline-template.csv').open()))
for line in readrows('worked-timeline.csv'):
 assert line['original_zone']=='UTC' and line['clock_uncertainty'] and line['confidence'] in ['observed_synthetic','tentative','unavailable','unresolved']
 refs=line['frame_or_event'].split(';')
 if line['source_id'] in ['practice.pcap','protocol-examples.pcap']:
  source=idx if line['source_id']=='practice.pcap' else pi;assert all(int(n) in source for n in refs);assert any(abs(float(source[int(n)]['frame.time_epoch'])-parse(line['original_time']))<.000001 for n in refs)
 elif line['source_id']=='identity-events.csv':assert line['original_time']==ev[refs[0]]['original_time']
 else:assert line['source_id']=='maintenance.md' and refs==['M01'] and line['original_time']=='2026-01-01T00:00:00.000'
assert next(csv.reader((r/'worked-asset-shortlist.csv').open()))==next(csv.reader((r/'asset-shortlist-template.csv').open()))
assert {x['system'] for x in readrows('worked-asset-shortlist.csv')}==set(mapping.values())
for row in readrows('worked-asset-shortlist.csv'):
 assert row['system'] in mapping.values() and row['supporting_refs'] and row['scope_classification']=='potentially_involved'
 if row['system']=='LAB-CLIENT':assert 'no target-host authentication outcome' in row['corroborated_outcome'] and 'process ownership' in row['unresolved_question']
 if row['system']=='APP-C':assert row['responding_peer']=='unknown' and 'no host records' in row['corroborated_outcome']
key=(r/'answer-key.md').read_text();assert all(x in key for x in ['11,12,19,20','23frames','5TCP','0x18','0x19','EV05','4776','protocol-examples.pcap','14frames','8/9/10','worked-timeline.csv','worked-asset-shortlist.csv'])
files=['practice.pcap','identity-events.csv','discovery-map.csv','address-map.csv','coverage.csv','fixture-spec.json','case-evidence-inventory.csv','timeline-template.csv','asset-shortlist-template.csv','discovery-map-template.csv']
with tempfile.TemporaryDirectory() as td:
 for builder,folder,names in [('build_fixture.py','main',files),('build_protocol_examples.py','protocol',['protocol-examples.pcap','protocol-examples-spec.json'])]:
  out=Path(td)/folder;cmd=[sys.executable,str(r/builder),'--out-dir',str(out)];first=subprocess.run(cmd,capture_output=True,text=True);assert first.returncode==0,first.stderr
  for name in names:assert (r/name).read_bytes()==(out/name).read_bytes(),name
  refusal=subprocess.run(cmd,capture_output=True,text=True);assert refusal.returncode!=0 and 'Refusing existing output directory' in refusal.stderr
print(json.dumps({'verdict':'pass','primaryFrames':23,'protocolExampleFrames':14,'primaryLdapFrames':[11,12,19,20],'kerberosErrorCodes':[24,25],'ntlmsspTypes':[1,2,3],'ntlmFinalHttpStatus':401,'identityRows':5,'malformed':0,'badChecksums':0,'mainGeneratedFilesCompared':len(files),'protocolGeneratedFilesCompared':2,'bothOverwriteAttempts':'refused','discoveryDirectionsFlagsAndPeers':'verified against actual decoding','eventSourceMappingCoverageTimes':'verified','workedTimelineReferenceTimeAndSchema':'verified','workedShortlistClassificationAndSchema':'verified'}))
