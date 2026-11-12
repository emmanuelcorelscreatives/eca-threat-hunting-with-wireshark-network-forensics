#!/usr/bin/env python3
"""Independently decode supplied PCAP with TShark; no packet generation/import of builder."""
import argparse,csv,json,hashlib,subprocess,datetime,decimal
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--spec',required=True,type=Path);p.add_argument('--pcap',required=True,type=Path);p.add_argument('--expected',required=True,type=Path);p.add_argument('--tshark',default='tshark');a=p.parse_args();spec=json.loads(a.spec.read_text());fields=['frame.number','frame.time_epoch','ip.src','ip.dst','tcp.srcport','tcp.dstport','tcp.flags','tcp.seq_raw','tcp.ack_raw','udp.srcport','udp.dstport','data.data','icmp.type','icmp.code'];cmd=[a.tshark,'-r',str(a.pcap),'-n','-T','fields','-E','separator=|','-E','occurrence=a']
for f in fields:cmd+=['-e',f]
r=subprocess.run(cmd,check=True,capture_output=True,text=True);rows=[dict(zip(fields,line.split('|')))for line in r.stdout.splitlines()];assert len(rows)==14==len(spec['events'])
flags={'F':1,'S':2,'R':4,'P':8,'A':16,'U':32,'E':64,'C':128}
for n,(event,row)in enumerate(zip(spec['events'],rows),1):
 assert int(row['frame.number'])==n
 t=datetime.datetime.fromisoformat(event['timestamp'].replace('Z','+00:00'));assert decimal.Decimal(row['frame.time_epoch'])==decimal.Decimal(str(t.timestamp()))
 assert row['ip.src'].split(',')[0]==event['src'] and row['ip.dst'].split(',')[0]==event['dst']
 if event['kind']=='tcp':
  assert int(row['tcp.srcport'])==event['sport'] and int(row['tcp.dstport'])==event['dport'];assert int(row['tcp.flags'],16)==sum(flags[c]for c in event['flags']);assert int(row['tcp.seq_raw'])==event['seq'] and int(row['tcp.ack_raw'])==event['ack']
 if event['kind']=='udp':
  assert int(row['udp.srcport'])==event['sport'] and int(row['udp.dstport'])==event['dport'];assert bytes.fromhex(row['data.data'].replace(':','')).decode()==event['payloadText']
 if event['kind']=='icmp-unreachable':
  quoted=spec['events'][event['quoteEvent']-1];assert row['icmp.type']=='3' and row['icmp.code']=='1';assert row['ip.src'].split(',')[1]==quoted['src']and row['ip.dst'].split(',')[1]==quoted['dst'];assert int(row['udp.srcport'])==quoted['sport']and int(row['udp.dstport'])==quoted['dport']
# Check every completed map row against actual attempt/reply addresses, ports and timestamps.
key=list(csv.DictReader(a.expected.open()));assert len(key)==7
sha=hashlib.sha256(a.pcap.read_bytes()).hexdigest();all_attempts=[]
for k in key:
 assert k['source_file_id']==sha and k['coverage_note']and k['address_mapping_status']=='unknown'and k['authorization_status']=='unknown'
 attempts=[int(x)for x in k['attempt_frames'].split(';')];all_attempts+=attempts
 for n in attempts:
  row=rows[n-1];assert row['ip.src']==k['observed_initiator_ip']and row['ip.dst']==k['observed_target_ip'];assert row[k['transport'].lower()+'.dstport']==k['destination_port']
 for field,n in [('first_attempt_utc',attempts[0]),('last_attempt_utc',attempts[-1])]:assert decimal.Decimal(rows[n-1]['frame.time_epoch'])==decimal.Decimal(str(datetime.datetime.fromisoformat(k[field].replace('Z','+00:00')).timestamp()))
 for text in filter(None,k['reply_frames'].split(';')):
  row=rows[int(text)-1];expected=k['responder_ip'] if int(text)!=3 else k['observed_initiator_ip'];assert row['ip.src'].split(',')[0]==expected
assert sorted(all_attempts)==[1,4,6,7,8,10,12,13]
assert len({k['observed_initiator_ip']for k in key})==2 and len({k['observed_target_ip']for k in key})==6
assert rows[5]['tcp.seq_raw']==rows[6]['tcp.seq_raw']=='3000'
assert [(i+1)for i,row in enumerate(rows)if row['tcp.flags']=='0x0002']==[1,4,6,7,12,13]
print(json.dumps({'verdict':'pass','frames':14,'matrixRows':7,'initiators':2,'distinctTargets':6,'synFrames':[1,4,6,7,12,13],'gatewayIcmpFrame':9,'payloadFrame11':'LAB-PONG','pcapSha256':sha,'allEventFieldsAndMatrixReferencesChecked':True}))
