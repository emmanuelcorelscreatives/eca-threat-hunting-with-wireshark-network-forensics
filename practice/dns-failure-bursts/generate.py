#!/usr/bin/env python3
"""Offline Academy DNS exercise. Standard library only; no sockets; never overwrite."""
import argparse,csv,datetime,ipaddress,json,struct
from pathlib import Path

def checksum(b):
 b+=b'\0'*(len(b)%2);s=sum(struct.unpack('!%dH'%(len(b)//2),b))
 while s>>16:s=(s&65535)+(s>>16)
 return (~s)&65535

def name(s):
 parts=s.rstrip('.').split('.')
 if any(not p or len(p)>63 or not p.isascii() for p in parts):raise ValueError('Invalid DNS name')
 return b''.join(bytes([len(p)])+p.encode('ascii') for p in parts)+b'\0'

def packet(r,response,index):
 src=ipaddress.IPv4Address(r['src']).packed;dst=ipaddress.IPv4Address(r['dst']).packed;sport=int(r['sport']);dport=53
 if response:src,dst=dst,src;sport,dport=dport,sport
 q=name(r['name'])+struct.pack('!HH',{'A':1,'AAAA':28}[r['qtype']],1)
 an=ns=0;rr=b'';flags=0x100
 if response:
  flags={'NOERROR':0x8180,'NXDOMAIN':0x8183}[r['rcode']]
  if r['answer_a']:
   an=1;rr=name(r['name'])+struct.pack('!HHIH',1,1,60,4)+ipaddress.IPv4Address(r['answer_a']).packed
  elif r['soa_zone']:
   ns=1;zone=r['soa_zone'];body=name('ns.'+zone)+name('hostmaster.'+zone)+struct.pack('!IIIII',1,3600,600,86400,int(r['soa_minimum_s']))
   rr=name(zone)+struct.pack('!HHIH',6,1,int(r['soa_ttl_s']),len(body))+body
 dns=struct.pack('!HHHHHH',int(r['id']),flags,1,an,ns,0)+q+rr
 length=8+len(dns);udp=struct.pack('!HHHH',sport,dport,length,0)+dns;uc=checksum(src+dst+struct.pack('!BBH',0,17,length)+udp) or 65535;udp=udp[:6]+struct.pack('!H',uc)+udp[8:]
 ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),index,0,64,17,0,src,dst);ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
 return b'\x02\x00'+dst+b'\x02\x00'+src+b'\x08\x00'+ip+udp

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--spec',type=Path,required=True);ap.add_argument('--out-dir',type=Path,required=True);a=ap.parse_args();spec=json.loads(a.spec.read_text());assert spec['schema']=='academy-dns-failure-bursts-1';rows=list(csv.DictReader((a.spec.parent/spec['transactions']).open()));notes=json.loads((a.spec.parent/spec['collectionNotes']).read_text());base=int(datetime.datetime.fromisoformat(notes['baseUtc'].replace('Z','+00:00')).timestamp())
 outputs=[a.out_dir/n for n in spec['outputsRelativeToFixturesDirectory'].values()]
 if any(p.exists() for p in outputs):raise FileExistsError('Refusing to overwrite any capture')
 payloads=[]
 for view,filename in spec['outputsRelativeToFixturesDirectory'].items():
  events=[]
  for r in rows:
   if r['view']!=view:continue
   events.append((int(r['query_ms']),0,r['row'],r))
   if r['reply_ms']:events.append((int(r['reply_ms']),1,r['row'],r))
  events.sort(key=lambda x:x[:3]);b=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
  for i,(ms,res,_,r) in enumerate(events,1):
   p=packet(r,res,i);b+=struct.pack('<IIII',base+ms//1000,(ms%1000)*1000,len(p),len(p))+p
  payloads.append((a.out_dir/filename,b))
 a.out_dir.mkdir(parents=True,exist_ok=True)
 for p,b in payloads:
  with p.open('xb') as f:f.write(b)
 print(json.dumps({'synthetic':True,'networkTrafficSent':False,'files':[{ 'name':p.name,'bytes':len(b)} for p,b in payloads]}))
if __name__=='__main__':main()
