#!/usr/bin/env python3
"""Offline deterministic multi-interface observation fixture. Sends no packets."""
import argparse,struct,pathlib,hashlib,json
p=argparse.ArgumentParser();p.add_argument('--output',required=True);a=p.parse_args()
src=pathlib.Path(__file__).with_name('practice.pcap').read_bytes()
if hashlib.sha256(src).hexdigest()!='a515f36e0e32a7079145d087a9f226d798bb81549cec01f93b31c33cad1b9968':raise SystemExit('Source hash mismatch')
def block(t,b):
 b+=b'\0'*((-len(b))%4);n=len(b)+12;return struct.pack('<II',t,n)+b+struct.pack('<I',n)
def option(t,b):return struct.pack('<HH',t,len(b))+b+b'\0'*((-len(b))%4)
b=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))
for name in [b'synthetic-observer-A',b'synthetic-observer-B']:
 b+=block(1,struct.pack('<HHI',1,0,65535)+option(2,name)+option(9,b'\x06')+option(0,b''))
o=24;i=0
while o<len(src):
 sec,usec,cap,orig=struct.unpack_from('<IIII',src,o);o+=16;packet=src[o:o+cap];o+=cap;i+=1
 def epb(iface,ts):return block(6,struct.pack('<IIIII',iface,ts>>32,ts&0xffffffff,cap,orig)+packet)
 b+=epb(0,sec*1000000+usec)
 if i==4:b+=epb(1,sec*1000000+usec+1)
out=pathlib.Path(a.output)
with out.open('xb') as f:f.write(b)
print(json.dumps({'synthetic':True,'frames':17,'interfaces':2,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}))
