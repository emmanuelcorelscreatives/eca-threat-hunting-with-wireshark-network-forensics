#!/usr/bin/env python3
"""Offline standard-library PCAPNG fixture builder. Sends no traffic; refuses overwrite."""
import argparse,json,pathlib,struct,socket,hashlib

def cs(b):
 if len(b)%2:b+=b'\0'
 n=sum(struct.unpack('!%dH'%(len(b)//2),b));n=(n&65535)+(n>>16);n=(n&65535)+(n>>16);return (~n)&65535

def generate(s):
 packets=[]
 def packet(t,src,dst,proto,payload):
  a=socket.inet_aton(src);b=socket.inet_aton(dst);h=struct.pack('!BBHHHBBH4s4s',69,0,20+len(payload),len(packets)+1,0,64,proto,0,a,b);h=h[:10]+struct.pack('!H',cs(h))+h[12:];packets.append((round((s['epoch']+t)*1e6),bytes.fromhex('0200000000020200000000010800')+h+payload))
 def tcp(t,a,b,sp,dp,seq,ack,flags,data=b''):
  h=struct.pack('!HHIIBBHHH',sp,dp,seq,ack,80,flags,65535,0,0)+data;check=cs(socket.inet_aton(a)+socket.inet_aton(b)+struct.pack('!BBH',0,6,len(h))+h);packet(t,a,b,6,h[:16]+struct.pack('!H',check)+h[18:])
 def dns(t,host,name,answer,ident,port):
  q=b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',1,1)
  for dt,src,dst,sp,dp,data in [(0,host,'192.0.2.53',port,53,struct.pack('!HHHHHH',ident,0x100,1,0,0,0)+q),(.02,'192.0.2.53',host,53,port,struct.pack('!HHHHHH',ident,0x8180,1,1,0,0)+q+b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+socket.inet_aton(answer))]:
   h=struct.pack('!HHHH',sp,dp,8+len(data),0)+data;packet(t+dt,src,dst,17,h)
 def record(kind,body):
  h=bytes([kind])+len(body).to_bytes(3,'big')+body;return b'\x16\x03\x03'+len(h).to_bytes(2,'big')+h
 dns(0,'192.0.2.10','peer.candidate.test','198.51.100.20',4001,53001);dns(.03,'192.0.2.20','updates.agent.example','203.0.113.20',4002,53002);dns(.06,'192.0.2.10','other.candidate.test','203.0.113.30',4003,53003)
 for index,c in enumerate(s['sessions']):
  a,b,sp,t,x,y=c['host'],c['peer'],c['port'],c['start'],c['client_isn'],c['server_isn'];tcp(t,a,b,sp,443,x,0,2);tcp(t+.02,b,a,443,sp,y,x+1,18);tcp(t+.04,a,b,sp,443,x+1,y+1,16);x+=1;y+=1
  name=c['name'].encode();sni=struct.pack('!H',len(name)+3)+b'\0'+struct.pack('!H',len(name))+name;ext=struct.pack('!HH',0,len(sni))+sni
  hello=record(1,b'\x03\x03'+bytes([index+1])*32+b'\0'+b'\0\x02\0\x2f'+b'\x01\0'+struct.pack('!H',len(ext))+ext)
  reply=record(2,b'\x03\x03'+bytes([index+10])*32+b'\0'+b'\0\x2f\0'+b'\0\0')
  tcp(t+.06,a,b,sp,443,x,y,24,hello);x+=len(hello);tcp(t+.08,b,a,443,sp,y,x,24,reply);y+=len(reply);tcp(t+.10,a,b,sp,443,x,y,16)
 def block(kind,data):
  data+=b'\0'*((-len(data))%4);size=len(data)+12;return struct.pack('<II',kind,size)+data+struct.pack('<I',size)
 out=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))+block(1,struct.pack('<HHI',1,0,65535))
 for us,p in sorted(packets):out+=block(6,struct.pack('<IIIII',0,us>>32,us&0xffffffff,len(p),len(p))+p)
 return out
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--spec',default='fixture-spec.json');p.add_argument('--output',required=True);a=p.parse_args();b=generate(json.loads(pathlib.Path(a.spec).read_text()))
 with open(a.output,'xb') as f:f.write(b)
 print(json.dumps({'synthetic':True,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}))
