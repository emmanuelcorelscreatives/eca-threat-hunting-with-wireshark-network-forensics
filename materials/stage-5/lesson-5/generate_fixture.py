#!/usr/bin/env python3
"""Convert the supplied synthetic PCAP to deterministic unannotated pcapng, offline."""
from pathlib import Path
import sys,struct,hashlib,json
if len(sys.argv)!=3: raise SystemExit('Usage: python generate_fixture.py practice.pcap NEW_OUTPUT.pcapng')
src,dst=map(Path,sys.argv[1:]); b=src.read_bytes()
if hashlib.sha256(b).hexdigest()!='92c4ba93b14ffc744e19c9371eb9546c6d16a0fac27c5dfcc935fff30901eae6': raise SystemExit('Unexpected source PCAP')
def block(t,b):
 b+=b'\0'*((-len(b))%4);n=len(b)+12;return struct.pack('<II',t,n)+b+struct.pack('<I',n)
o=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))+block(1,struct.pack('<HHI',1,0,65535));p=24
while p<len(b):
 s,u,inc,orig=struct.unpack_from('<IIII',b,p);p+=16;pkt=b[p:p+inc];p+=inc;ts=s*1000000+u;o+=block(6,struct.pack('<IIIII',0,ts>>32,ts&0xffffffff,inc,orig)+pkt+b'\0'*((-inc)%4))
with dst.open('xb') as f:f.write(o)
print(json.dumps({'synthetic':True,'bytes':len(o),'sha256':hashlib.sha256(o).hexdigest()}))
