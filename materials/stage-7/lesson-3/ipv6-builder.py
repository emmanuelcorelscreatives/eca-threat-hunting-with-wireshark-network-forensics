#!/usr/bin/env python3
"""Deterministic documentation-only IPv6 UDP capture; no network activity."""
import argparse,ipaddress,struct,hashlib,json
from pathlib import Path
def checksum(data):
 data+=b'\0' if len(data)%2 else b''
 s=sum(struct.unpack('!%dH'%(len(data)//2),data))
 while s>>16:s=(s&65535)+(s>>16)
 return (~s)&65535
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
b=bytearray(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
for i,(s,t,sp,dp,payload) in enumerate([('2001:db8::10','2001:db8::20',55000,9000,b'ACADEMY'),('2001:db8::20','2001:db8::10',9000,55000,b'ACK'),('2001:db8::10','2001:db8::30',55001,9000,b'CHECK')]):
 src=ipaddress.IPv6Address(s).packed;dst=ipaddress.IPv6Address(t).packed;n=8+len(payload)
 udp=struct.pack('!HHHH',sp,dp,n,0)+payload;c=checksum(src+dst+struct.pack('!I3xB',n,17)+udp) or 65535
 udp=struct.pack('!HHHH',sp,dp,n,c)+payload
 frame=bytes.fromhex('02000000000202000000000186dd')+struct.pack('!IHBB',6<<28,n,17,64)+src+dst+udp
 b+=struct.pack('<IIII',1738576800+i,0,len(frame),len(frame))+frame
with a.output.open('xb') as f:f.write(b)
print(json.dumps({'synthetic':True,'frames':3,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}))
