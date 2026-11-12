#!/usr/bin/env python3
"""Deterministic offline teaching simulation. No network access; refuses overwrite."""
import argparse,struct,socket,hashlib,json,csv,pathlib

def checksum(b):
 b+=b'\0'*(len(b)%2); s=sum(struct.unpack('!%dH'%(len(b)//2),b)); s=(s&65535)+(s>>16);s=(s&65535)+(s>>16);return (~s)&65535

def ip4(payload,ident,offset=0,mf=False,proto=17):
 src=socket.inet_aton('192.0.2.10');dst=socket.inet_aton('198.51.100.20')
 h=struct.pack('!BBHHHBBH4s4s',69,0,20+len(payload),ident,offset|(8192 if mf else 0),64,proto,0,src,dst)
 return h[:10]+struct.pack('!H',checksum(h))+h[12:]+payload

def ip6(payload,ident,offset=0,more=False):
 frag=struct.pack('!BBHI',17,0,(offset<<3)|int(more),ident)
 return struct.pack('!IHBB16s16s',6<<28,len(frag)+len(payload),44,64,socket.inet_pton(socket.AF_INET6,'2001:db8::10'),socket.inet_pton(socket.AF_INET6,'2001:db8::20'))+frag+payload

def eth(p,v6=False):return bytes.fromhex('020000000002020000000001')+struct.pack('!H',34525 if v6 else 2048)+p

def tcp(seq,data,good=True):
 src=socket.inet_aton('192.0.2.10');dst=socket.inet_aton('198.51.100.20')
 h=struct.pack('!HHIIBBHHH',41000,9000,seq,1,80,24,65535,0,0)
 c=checksum(src+dst+struct.pack('!BBH',0,6,len(h)+len(data))+h+data) if good else 0
 return h[:16]+struct.pack('!H',c)+h[18:]+data

def block(t,b):
 b+=b'\0'*((-len(b))%4);n=len(b)+12;return struct.pack('<II',t,n)+b+struct.pack('<I',n)

def build():
 packets=[];rows=[]
 def add(case,p,role,notes,wire=None):
  n=len(packets)+1;packets.append((p,wire or len(p)));rows.append(dict(frame=n,case=case,role=role,captured_length=len(p),reported_length=wire or len(p),notes=notes,observation_point='authored simulation; no measured interface',direction='authored A to B',window='authored 2023-11-14T22:13:20Z plus 0.1 seconds per frame',collection_filter='none: generated file',drop_count='not applicable; no collector'))
 udp=struct.pack('!HHHH',40000,9000,40,0)+b'0123456789abcdefghijklmnopqrstuv'
 add('ipv4-complete',eth(ip4(udp[:24],100,0,True)),'first','IP payload bytes 0-23; MF=1')
 add('ipv4-complete',eth(ip4(udp[24:],100,3,False)),'last','IP payload bytes 24-39; offset field 3 eight-byte units')
 add('ipv4-incomplete',eth(ip4(udp[:24],101,0,True)),'first-only','No final fragment supplied; cannot infer where missing bytes were lost')
 # IPv6 requires a nonzero UDP checksum. Compute it over the complete upper layer.
 s6=socket.inet_pton(socket.AF_INET6,'2001:db8::10');d6=socket.inet_pton(socket.AF_INET6,'2001:db8::20');v6udp=udp[:6]+struct.pack('!H',checksum(s6+d6+struct.pack('!I3xB',len(udp),17)+udp))+udp[8:]
 add('ipv6-split',eth(ip6(v6udp[:24],200,0,True),True),'first','Fragment header offset 0 more=1')
 add('ipv6-split',eth(ip6(v6udp[24:],200,3,False),True),'last','Fragment header offset 3 more=0')
 add('ipv6-atomic',eth(ip6(v6udp,201,0,False),True),'atomic','Fragment header present but offset=0 more=0; complete in one packet')
 p=eth(ip4(udp,102));add('truncation',p[:42],'shortened','Saved bytes shorter than reported frame; distinct from IP fragmentation',len(p))
 data=b'X'*3000
 add('offload-host-simulation',eth(ip4(tcp(1000,data,False),300,proto=6)),'host aggregate','SIMULATED pre-segmentation 3000 TCP bytes; checksum placeholder zero; no real hardware claim')
 for i in range(3):add('offload-wire-simulation',eth(ip4(tcp(1000+i*1000,data[i*1000:(i+1)*1000]),301+i,proto=6)),'segment','SIMULATED post-segmentation 1000 TCP bytes; valid computed checksum; paired conceptual view, not independent measured observation')
 out=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))+block(1,struct.pack('<HHI',1,0,65535))
 for i,(p,w) in enumerate(packets):
  ts=1700000000000000+i*100000;out+=block(6,struct.pack('<IIIII',0,ts>>32,ts&0xffffffff,len(p),w)+p)
 return out,rows

def main():
 a=argparse.ArgumentParser();a.add_argument('--output');a.add_argument('--manifest',required=True);a.add_argument('--verify',action='store_true');a.add_argument('--capture');x=a.parse_args();data,rows=build()
 import io
 s=io.StringIO(newline='');w=csv.DictWriter(s,fieldnames=list(rows[0]),lineterminator='\n');w.writeheader();w.writerows(rows);manifest=s.getvalue().encode()
 if x.verify:
  if not x.capture: a.error('--capture required with --verify')
  if pathlib.Path(x.capture).read_bytes()!=data or pathlib.Path(x.manifest).read_bytes()!=manifest:raise SystemExit('Verification failed: exact deterministic bytes differ')
 else:
  if not x.output:a.error('--output required')
  if pathlib.Path(x.output).exists() or pathlib.Path(x.manifest).exists():raise SystemExit('Refusing to overwrite existing capture or manifest')
  with open(x.output,'xb') as f:f.write(data)
  with open(x.manifest,'xb') as f:f.write(manifest)
 print(json.dumps(dict(synthetic=True,frames=len(rows),bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),verified=x.verify)))
if __name__=='__main__':main()
