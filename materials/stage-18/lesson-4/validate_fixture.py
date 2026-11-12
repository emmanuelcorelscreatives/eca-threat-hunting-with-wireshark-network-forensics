#!/usr/bin/env python3
"""Independent raw classic-PCAP and scenario-record checks. Reads files only."""
import argparse,struct,hashlib,json,csv,ipaddress,datetime
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);a=p.parse_args();r=a.root

def checksum(d):
 if len(d)%2:d+=b'\0'
 n=sum(struct.unpack('!%dH'%(len(d)//2),d))
 while n>>16:n=(n&65535)+(n>>16)
 return n==65535
# Expected identities were independently established from the exact reviewed final files.
EXPECTED_CAPTURES={"ab":"fa7ab10a6bad8bf622ebaf52beae9de6749887cc1fa187ec644a1d1d3f9469e5","bc":"505f37cd8c25401b9c3bb0feb34f6e698ef4b6aaf3fda9e35fcd6da4db64749d"}
EXPECTED_RECORDS={'capture_inventory.csv': '567e306a518977b655cc1e7f896b13d5bf4465aa69b42e879c96d0e9773da53b', 'address_assignments.csv': '304b3d966bbe3eb21647060682d83626f4a9eaf70a5dbdcfec57c7f75a46ecfe', 'host_events.csv': '05df1cf7012de015bc03faecfaf718e8d9a8a150da6bf95c13d2bae506185ded', 'identity_events.csv': '96c5df4e4a87d4b32939b6e2f231c47ed5b8cd81b157092cec377aa976b14587', 'work_orders.csv': 'b7581656c70aefce9d93cfb0bf2680f2d47579f5ae76d1602e39d6ffd78a8bd4', 'identity_and_work_orders.json': '14634434c3b40ce3e9143f2a2dbf2872ce8194356469574f6b05798b3c2958e8'}
for filename,digest in EXPECTED_RECORDS.items():
 assert hashlib.sha256((r/filename).read_bytes()).hexdigest()==digest, 'Scenario file differs from validated assignment/coverage/session/identity/work-order records: '+filename
records=lambda n:list(csv.DictReader((r/n).open()))
instant=lambda t:datetime.datetime.fromisoformat(t.replace('Z','+00:00'))
coverage={x['capture_id']:x for x in records('capture_inventory.csv')}
for name,link,excluded,t in [('ab','A-B bidirectional','B-C','2026-01-15T10:00:00Z'),('bc','B-C bidirectional','A-B','2026-01-15T10:02:01Z')]:
 row=coverage[name];assert row['relative_file']==name+'.pcap' and row['covered_link']==link and row['excluded_link']==excluded
 assert instant(row['window_start_utc'])<=instant(t)<instant(row['window_end_utc'])
 assert row['time_basis']=='authored UTC timestamps' and row['clock_offset_status']=='no physical offset measured'
assign={x['asset_label']:x for x in records('address_assignments.csv')}
for label,address in [('A','192.0.2.10'),('B','192.0.2.20'),('C','192.0.2.30')]:
 row=assign[label];assert row['ipv4']==address
 for t in ['2026-01-15T10:00:00Z','2026-01-15T10:02:01Z']:
  assert instant(row['valid_from_utc'])<=instant(t)<instant(row['valid_to_utc'])
host={x['event_id']:x for x in records('host_events.csv')};ident={x['event_id']:x for x in records('identity_events.csv')};order=records('work_orders.csv')[0]
assert host['H-B-1']['account']==ident['I-AB']['account']=='ops_lee'
assert host['H-B-1']['src_ip']==ident['I-AB']['source_ip']=='192.0.2.10' and ident['I-AB']['target_host']=='B' and ident['I-AB']['session_ref']=='AB-001'
job=host['H-B-2'];process=host['H-B-3'];access=ident['I-BC']
assert job['account']==process['account']==access['account']==order['account']=='svc_deploy'
assert process['parent_pid']==job['pid']=='4100' and process['pid']=='4101'
assert job['job_id']==process['job_id']==order['job_id']=='DEPLOY-42'
assert process['src_ip']==access['source_ip']=='192.0.2.20' and process['dst_ip']=='192.0.2.30' and process['src_port']=='52022' and process['dst_port']=='2222'
assert instant(job['ts_utc'])<instant(process['ts_utc'])<instant('2026-01-15T10:02:01Z')<instant(access['ts_utc'])
assert order['work_id']=='M-42' and order['source_asset']=='B' and order['target_asset']=='C' and order['transport']=='TCP' and order['destination_port']=='2222' and order['status']=='approved'
assert instant(order['valid_from_utc'])<=instant(process['ts_utc'])<instant(order['valid_to_utc'])
assert all(x['outcome']=='success' for x in ident.values()) # Synthetic reported success, never decoded packet authentication.

results=[]
for name,src,dst,start in [('ab','192.0.2.10','192.0.2.20',1768471200),('bc','192.0.2.20','192.0.2.30',1768471321)]:
 data=(r/(name+'.pcap')).read_bytes();assert hashlib.sha256(data).hexdigest()==EXPECTED_CAPTURES[name], 'Exact capture identity mismatch';assert struct.unpack('<IHHIIII',data[:24])==(0xa1b2c3d4,2,4,0,0,65535,1)
 off=24;frames=[]
 while off<len(data):
  sec,usec,inc,orig=struct.unpack('<IIII',data[off:off+16]);off+=16;f=data[off:off+inc];off+=inc
  assert inc==orig==len(f) and len(f)>=60 and f[12:14]==b'\x08\x00'
  ip=f[14:];ihl=(ip[0]&15)*4;length=struct.unpack('!H',ip[2:4])[0];assert checksum(ip[:ihl]) and ip[9]==6
  tcp=ip[ihl:length];assert checksum(ip[12:20]+struct.pack('!BBH',0,6,len(tcp))+tcp)
  source=str(ipaddress.ip_address(ip[12:16]));dest=str(ipaddress.ip_address(ip[16:20]));assert {source,dest}=={src,dst}
  frames.append(dict(frame=len(frames)+1,time=sec+usec/1e6,source=source,destination=dest,flags=tcp[13],length=inc))
 assert off==len(data) and len(frames)==10 and sum(f['length'] for f in frames)==620
 assert abs(frames[0]['time']-start)<.00001 and abs(frames[-1]['time']-start-5.2)<.00001
 assert [f['flags'] for f in frames]==[2,18,16,24,16,24,16,17,17,16]
 results.append(dict(capture=name,bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),frames=frames))
scenario=json.loads((r/'identity_and_work_orders.json').read_text())
for key in ['identity_events','work_orders']:
 rows=list(csv.DictReader((r/(key+'.csv')).open()));assert rows==[{k:str(v) for k,v in row.items()} for row in scenario[key]]
assert {row['capture_id'] for row in csv.DictReader((r/'capture_inventory.csv').open())}=={'ab','bc'}
assert len(list(csv.DictReader((r/'address_assignments.csv').open())))==3
assert {x['event_id'] for x in csv.DictReader((r/'host_events.csv').open())}=={'H-B-1','H-B-2','H-B-3'}
print(json.dumps(dict(verdict='pass',scope='Independent raw bytes/checksums, separate numbering/timestamps/edges/counts and scenario record cross-checks; no causal or GUI conclusion',captures=results),indent=2))
