#!/usr/bin/env python3
"""Offline standard-library synthetic TCP coursework; refuses overwrite."""
import argparse,json,struct,socket,pathlib

def checksum(b):
 if len(b)%2:b+=b'\0'
 s=sum(struct.unpack('!%dH'%(len(b)//2),b));s=(s>>16)+(s&65535);s+=(s>>16);return (~s)&65535

def generate(spec):
 packets=[];ident=0
 def emit(t,src,dst,sp,dp,seq,ack,flags,data=b''):
  nonlocal ident
  ident+=1;a=socket.inet_aton(src);b=socket.inet_aton(dst)
  tcp=struct.pack('!HHIIBBHHH',sp,dp,seq,ack,80,flags,65535,0,0)+data
  cs=checksum(a+b+struct.pack('!BBH',0,6,len(tcp))+tcp);tcp=tcp[:16]+struct.pack('!H',cs)+tcp[18:]
  ip=struct.pack('!BBHHHBBH4s4s',69,0,20+len(tcp),ident,0,64,6,0,a,b);ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
  eth=bytes.fromhex('0200000000020200000000010800');packets.append((round((spec['epoch']+t)*1e6),eth+ip+tcp))
 for c in spec['connections']:
  client=spec['asset'];peer=c['peer'];sp=c['client_port'];dp=c['peer_port'];t=c['start'];x=c['client_isn'];y=c['server_isn']
  emit(t,client,peer,sp,dp,x,0,2);emit(t+.01,peer,client,dp,sp,y,x+1,18);emit(t+.02,client,peer,sp,dp,x+1,y+1,16);x+=1;y+=1
  for dt in c['exchange_offsets']:
   req=b'LAB_REQUEST';res=b'LAB_REPLY';emit(t+dt,client,peer,sp,dp,x,y,24,req);x+=len(req);emit(t+dt+.01,peer,client,dp,sp,y,x,24,res);y+=len(res);emit(t+dt+.02,client,peer,sp,dp,x,y,16)
  for dt in c.get('probe_offsets',[]):
   emit(t+dt,client,peer,sp,dp,x-1,y,16);emit(t+dt+.01,peer,client,dp,sp,y,x,16)
  end=t+c['duration'];emit(end,client,peer,sp,dp,x,y,17);x+=1;emit(end+.01,peer,client,dp,sp,y,x,17);y+=1;emit(end+.02,client,peer,sp,dp,x,y,16)
 packets.sort(key=lambda p:p[0]);out=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
 for us,b in packets:out+=struct.pack('<IIII',us//1000000,us%1000000,len(b),len(b))+b
 return out
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--spec',default='fixture_spec.json');p.add_argument('--output',required=True);a=p.parse_args();s=json.loads(pathlib.Path(a.spec).read_text());b=generate(s)
 with open(a.output,'xb') as f:f.write(b)
 print(json.dumps({'output':a.output,'bytes':len(b),'synthetic':True}))
