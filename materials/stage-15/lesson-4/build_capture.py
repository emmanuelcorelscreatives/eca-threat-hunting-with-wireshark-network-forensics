#!/usr/bin/env python3
"""Build only the supplied harmless offline TXT exercise. Never sends packets."""
import argparse,struct,socket,json,datetime
from pathlib import Path
def ck(b):
 if len(b)%2:b+=b'\0'
 n=sum(struct.unpack('!%dH'%(len(b)//2),b))
 while n>>16:n=(n&65535)+(n>>16)
 return (~n)&65535
def build(m):
 d=m['dns'];n=b''.join(bytes([len(x)])+x.encode('ascii') for x in d['name'].split('.'))+b'\0';q=n+struct.pack('!HH',16,1);v=m['marker']['intendedTxtValue'].encode('ascii');out=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
 for response in (False,True):
  dns=struct.pack('!HHHHHH',d['transactionId'],0x8180 if response else 0x100,1,int(response),0,0)+q
  if response:dns+=b'\xc0\x0c'+struct.pack('!HHIH',16,1,d['answerTtlSeconds'],len(v)+1)+bytes([len(v)])+v
  src=socket.inet_aton(d['resolverIp'] if response else d['clientIp']);dst=socket.inet_aton(d['clientIp'] if response else d['resolverIp']);ports=(d['resolverPort'],d['clientPort']) if response else (d['clientPort'],d['resolverPort']);u=struct.pack('!HHHH',*ports,len(dns)+8,0)+dns;check=ck(src+dst+struct.pack('!BBH',0,17,len(u))+u) or 65535;u=u[:6]+struct.pack('!H',check)+u[8:];ip=struct.pack('!BBHHHBBH4s4s',0x45,0,len(u)+20,1+int(response),0,64,17,0,src,dst);ip=ip[:10]+struct.pack('!H',ck(ip))+ip[12:];frame=bytes.fromhex('0200000000020200000000010800')+ip+u
  t=datetime.datetime.fromisoformat(d['responseUtc' if response else 'queryUtc'].replace('Z','+00:00'));epoch=int(t.timestamp());out+=struct.pack('<IIII',epoch,t.microsecond,len(frame),len(frame))+frame
 return out
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--reference',default='marker.json');p.add_argument('--output',required=True);a=p.parse_args();b=build(json.loads(Path(a.reference).read_text()));target=Path(a.output)
 with target.open('xb') as f:f.write(b)
 print(json.dumps({'bytes':len(b),'packets':2,'networkTrafficSent':False}))
