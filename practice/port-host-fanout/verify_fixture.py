#!/usr/bin/env python3
"""Independent binary reader: checks actual Ethernet/IP/TCP versus CSV and expected counts. Offline only."""
import argparse,csv,datetime as dt,ipaddress,json,struct
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--plan',type=Path,required=True);p.add_argument('--capture',type=Path,required=True);p.add_argument('--context',type=Path,required=True);p.add_argument('--expected',type=Path,required=True);a=p.parse_args()
def check(b):
 if len(b)%2:b+=b'\0'
 s=sum(struct.unpack('!%dH'%(len(b)//2),b))
 while s>>16:s=(s&65535)+(s>>16)
 return s==65535
b=a.capture.read_bytes();assert b[:4]==bytes.fromhex('d4c3b2a1');assert struct.unpack_from('<I',b,20)[0]==1
rows=list(csv.DictReader(a.plan.open()));off=24;frames=[]
for i,x in enumerate(rows,1):
 sec,mic,cap,orig=struct.unpack_from('<IIII',b,off);off+=16;f=b[off:off+cap];off+=cap;assert cap==orig==54
 client=bytes.fromhex('020000000010');gateway=bytes.fromhex('020000000001');s,d=(client,gateway)if x['src_ip']=='192.0.2.10'else(gateway,client)
 assert f[:14]==d+s+b'\x08\x00';ip=f[14:34];tcp=f[34:];assert check(ip);assert check(ip[12:20]+struct.pack('!BBH',0,6,len(tcp))+tcp)
 assert str(ipaddress.ip_address(ip[12:16]))==x['src_ip'];assert str(ipaddress.ip_address(ip[16:20]))==x['dst_ip'];assert struct.unpack('!HHII',tcp[:12])==(int(x['src_port']),int(x['dst_port']),int(x['seq']),int(x['ack']))
 assert tcp[13]=={'S':2,'SA':18,'A':16}[x['tcp_flags']]
 actual=dt.datetime.fromtimestamp(sec,dt.timezone.utc).replace(microsecond=mic);assert actual==dt.datetime.fromisoformat(x['timestamp_utc'].replace('Z','+00:00'))
 frames.append(dict(frame=i,**x))
assert off==len(b);e=json.loads(a.expected.read_text());assert len(rows)==e['packetCount'];assert [i for i,x in enumerate(rows,1)if x['tcp_flags']=='S']==e['synWithoutAckEventOrdinals'];assert [i for i,x in enumerate(rows,1)if x['tcp_flags']=='SA']==e['synAckEventOrdinals'];assert [i for i,x in enumerate(rows,1)if x['tcp_flags']=='A']==e['thirdAckEventOrdinals']
attempts=[(i,x)for i,x in enumerate(rows,1)if x['tcp_flags']=='S'];seen=set();repeats=[]
for i,x in attempts:
 key=tuple(x[v]for v in ['src_ip','src_port','dst_ip','dst_port','seq'])
 if key in seen:repeats.append(i)
 seen.add(key)
assert repeats==e['repeatEventOrdinals']
for kind,field,match in [('portFanOut','dst_port',lambda x:x['src_ip']==e['portFanOut']['source']and x['dst_ip']==e['portFanOut']['target']),('hostFanOut','dst_ip',lambda x:x['src_ip']==e['hostFanOut']['source']and int(x['dst_port'])==e['hostFanOut']['destinationPort'])]:
 first={}
 for i,x in attempts:
  if match(x)and x[field]not in first:first[x[field]]=(i,x['timestamp_utc'])
 assert len(first)==e[kind].get('distinctPortCount',e[kind].get('distinctTargetCount'))
 for want in e[kind]['firstAttempts']:
  key=str(want.get('dstPort',want.get('target')));assert first[key]==(want['eventOrdinal'],want['firstUtc'])
c=json.loads(a.context.read_text());assert c['synthetic']and not c['natModeled']
print(json.dumps(dict(verdict='pass',frames=len(frames),checks=['every CSV field and timestamp','Ethernet client/gateway directions','IPv4/TCP checksums','SYN/reply/ACK/repeat ordinals','distinct port and target first attempts'],coverage='Authored context and declared gap are not independently measured collection facts.')))
