#!/usr/bin/env python3
"""Independently parse PCAP records and decode supplied synthetic fixtures."""
from pathlib import Path
import argparse,struct,subprocess,os,json,tempfile,hashlib
p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,default=Path(__file__).resolve().parent);p.add_argument('--export',type=Path);a=p.parse_args()
def tool(n):
 d=Path(os.environ.get('WIRESHARK_BIN_DIR','/nonexistent'))/n
 return str(d) if d.is_file() else n
def read(path):
 b=path.read_bytes()
 if b[:4] not in (b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4'):
  with tempfile.TemporaryDirectory() as td:
   out=Path(td)/'converted.pcap';subprocess.run([tool('editcap'),'-F','pcap',str(path),str(out)],check=True,capture_output=True);return read(out)
 endian='<' if b[:4]==b'\xd4\xc3\xb2\xa1' else '>';out=[];offset=24
 while offset<len(b):
  sec,usec,n,orig=struct.unpack_from(endian+'IIII',b,offset);offset+=16;packet=b[offset:offset+n];offset+=n
  assert len(packet)==n==orig,'Truncated fixture'
  out.append({'frame':len(out)+1,'epoch':f'{sec}.{usec:06d}','packetSha256':hashlib.sha256(packet).hexdigest(),'bytes':n})
 assert offset==len(b);return out
def decode(path):
 fields=['frame.number','frame.time_epoch','frame.interface_id','ip.src','ip.dst','tcp.srcport','tcp.dstport','tcp.stream','tcp.len','tcp.seq_raw','tcp.ack_raw','dns.id','dns.qry.name','dns.a','ip.checksum.status','tcp.checksum.status','udp.checksum.status','_ws.malformed']
 cmd=[tool('tshark'),'-o','ip.check_checksum:TRUE','-o','tcp.check_checksum:TRUE','-o','udp.check_checksum:TRUE','-r',str(path),'-T','fields','-E','header=y']
 for f in fields:cmd+=['-e',f]
 z=subprocess.run(cmd,capture_output=True,text=True,check=True);rows=[dict(zip(fields,x.split('\t'))) for x in z.stdout.splitlines()[1:]]
 assert all(not x['_ws.malformed'] for x in rows),'Malformed frame'
 assert all(x['ip.checksum.status']=='1' for x in rows),'IP checksum'
 assert all(x['tcp.checksum.status'] in ('','1') and x['udp.checksum.status'] in ('','1') for x in rows),'Transport checksum'
 return {'argv':cmd,'stdout':z.stdout,'stderr':z.stderr,'rows':rows}
names=['original-a.pcap','original-b.pcap','reference-displayed-a.pcap','merged-time.pcapng'];raw={n:read(a.directory/n) for n in names};A,B,R,M=[raw[n] for n in names]
key=lambda x:(x['epoch'],x['packetSha256'])
assert [len(A),len(B),len(R),len(M)]==[6,3,2,9]
assert key(A[3])==key(B[1]);assert [key(x) for x in R]==[key(A[3]),key(A[4])]
assert sorted(key(x) for x in M)==sorted(key(x) for x in A+B)
assert [x['epoch'] for x in M]==sorted(x['epoch'] for x in M)
D={n:decode(a.directory/n) for n in names};ar=D[names[0]]['rows'];br=D[names[1]]['rows']
assert [int(x['frame.number']) for x in ar if int(x['tcp.len'] or 0)>0]==[4,5]
assert [int(x['tcp.len']) for x in ar]==[0,0,0,50,40,0]
assert [x['dns.qry.name'] for x in br]==['cite.example','','cite.example']
assert br[0]['dns.id']==br[2]['dns.id']=='0x1234' and br[2]['dns.a']=='198.51.100.20'
assert len({x['tcp.stream'] for x in ar})==1
mapping=[{'mergedFrame':x['frame'],'candidates':[{'file':n,'frame':y['frame']} for n in names[:2] for y in raw[n] if key(x)==key(y)],'status':'ambiguous duplicate' if key(x)==key(A[3]) else 'unique byte/time match within supplied sources'} for x in M]
if a.export:
 E=read(a.export);assert [key(x) for x in E]==[key(x) for x in R],'Export is not precisely A4/A5';decode(a.export)
report={'synthetic':True,'hostOS':Path('/etc/os-release').read_text(),'versions':{n:subprocess.run([tool(n),'--version'],capture_output=True,text=True,check=True).stdout.splitlines()[0] for n in ['tshark','editcap','mergecap']},'files':{n:{'sha256':hashlib.sha256((a.directory/n).read_bytes()).hexdigest(),'records':raw[n],'decode':D[n]} for n in names},'mergedMapping':mapping,'exportVerified':str(a.export) if a.export else None,'noCollectionProvenanceOrClockValidation':True}
print(json.dumps(report,indent=2))
