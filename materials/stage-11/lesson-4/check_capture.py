#!/usr/bin/env python3
"""Read-only independent raw PCAP integrity and scenario checker; no network use."""
import argparse,hashlib,ipaddress,json,struct
from pathlib import Path

def valid_sum(b):
 if len(b)%2:b+=b'\0'
 n=sum(struct.unpack('!%dH'%(len(b)//2),b))
 while n>>16:n=(n&65535)+(n>>16)
 return n==65535

def check(path,specpath):
 b=Path(path).read_bytes(); spec=json.loads(Path(specpath).read_text());assert b[:24]==struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1),'PCAP header'
 off=24;rows=[]
 for n,e in enumerate(spec['events'],1):
  sec,micro,cap,orig=struct.unpack_from('<IIII',b,off);off+=16;assert cap==orig,'truncation';p=b[off:off+cap];assert len(p)==cap;off+=cap
  assert p[12:14]==b'\x08\x00';ip=p[14:];assert ip[0]==0x45 and len(ip)==struct.unpack_from('!H',ip,2)[0];assert valid_sum(ip[:20]),'IPv4 checksum'
  src=str(ipaddress.ip_address(ip[12:16]));dst=str(ipaddress.ip_address(ip[16:20]));assert src==e['src'] and dst==e['dst'],'IP endpoints'
  from datetime import datetime,timezone
  timestamp=datetime.fromtimestamp(sec,timezone.utc).replace(microsecond=micro).isoformat().replace('+00:00','Z');assert datetime.fromisoformat(timestamp.replace('Z','+00:00'))==datetime.fromisoformat(e['timestamp'].replace('Z','+00:00')),'timestamp'
  t=ip[20:];sport,dport=struct.unpack_from('!HH',t);assert (sport,dport)==(e['sport'],e['dport'])
  pseudo=ip[12:20]+struct.pack('!BBH',0,ip[9],len(t));assert valid_sum(pseudo+t),'transport checksum'
  if ip[9]==17:
   assert struct.unpack_from('!H',t,4)[0]==len(t);d=t[8:];tid,flags,qd,an,ns,ar=struct.unpack_from('!6H',d);assert tid==e['transactionId'];assert bool(flags&0x8000)==e['kind'].endswith('answer')
   if e['kind'].startswith('nbns-'):
    encoded=d[13:45];name=bytes(((encoded[i]-65)<<4)|(encoded[i+1]-65) for i in range(0,32,2));assert name[:15].rstrip()==e['name'].encode() and name[15]==e['suffix'];qend=50
    if e.get('broadcast'):assert flags&16 and p[:6]==b'\xff'*6 and dst=='192.0.2.255'
   else:
    pos=12;labels=[]
    while d[pos]:length=d[pos];pos+=1;labels.append(d[pos:pos+length].decode());pos+=length
    assert '.'.join(labels)==e['name'];qend=pos+5
    if e['kind']=='llmnr-query':assert p[:6]==b'\x01\x00\x5e\x00\x00\xfc' and ip[8]==255
   if 'answer' in e:assert an==1 and str(ipaddress.ip_address(d[-4:]))==e['answer']
  else:
   assert ip[9]==6 and len(t)==20,'expected TCP no payload';seq,ack=struct.unpack_from('!II',t,4);assert (seq,ack)==(e['seq'],e['ack']);bits={'F':1,'S':2,'R':4,'P':8,'A':16,'U':32,'E':64,'C':128};assert t[13]==sum(bits[f] for f in e['flags'])
  rows.append({'frame':n,'kind':e['kind'],'src':src,'dst':dst,'bytes':cap})
 assert off==len(b),'extra/missing bytes';return {'verdict':'pass','frames':len(rows),'captureBytes':len(b),'packetBytes':sum(x['bytes'] for x in rows),'sha256':hashlib.sha256(b).hexdigest(),'checks':'PCAP records, timestamps, lengths, IPv4/UDP/TCP checksums, endpoints/ports, name IDs/questions/answers, multicast/broadcast MAC, TCP flags/sequences/no payload','rows':rows}
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('capture');a.add_argument('spec');o=a.parse_args();print(json.dumps(check(o.capture,o.spec),indent=2))
