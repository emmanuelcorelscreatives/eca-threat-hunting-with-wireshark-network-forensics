#!/usr/bin/env python3
"""Independent raw-PCAP checksum, framing and count verification. Reads only."""
import struct,sys,json,hashlib,ipaddress
from pathlib import Path
EXPECTED={'edge':(54,'590c129e8d740edb1e9490a5eb91f45907a96cc15076ca36fe1b7d1efc9e27f3'),'internal':(9,'c8330622a2f77a6fa562e68a0b84a4a3826ae56d34d77e10bd5ccf237a9da463')}
def valid_checksum(b):
 if len(b)%2:b+=b'\0'
 s=sum(struct.unpack('!%dH'%(len(b)//2),b))
 while s>>16:s=(s&65535)+(s>>16)
 return s==65535
def check(path,role):
 b=Path(path).read_bytes();n,h=EXPECTED[role]
 if hashlib.sha256(b).hexdigest()!=h:raise ValueError('Exact supplied fixture SHA256 mismatch')
 if len(b)<24 or struct.unpack('<IHHIIII',b[:24])!=(0xa1b2c3d4,2,4,0,0,65535,1):raise ValueError('Invalid global header')
 pos=24;frames=[];last=-1
 while pos<len(b):
  if pos+16>len(b):raise ValueError('Truncated record header')
  sec,usec,cap,wire=struct.unpack('<IIII',b[pos:pos+16]);pos+=16
  if cap!=wire or cap<54 or pos+cap>len(b) or usec>=1000000:raise ValueError('Invalid/truncated frame')
  p=b[pos:pos+cap];pos+=cap;t=sec*1000000+usec
  if t<last:raise ValueError('Unordered timestamps')
  last=t
  if p[12:14]!=b'\x08\x00' or p[14]!=0x45 or p[23]!=6:raise ValueError('Expected Ethernet IPv4 TCP')
  ip=p[14:];length=struct.unpack('!H',ip[2:4])[0]
  if length!=len(ip) or not valid_checksum(ip[:20]):raise ValueError('IPv4 length/checksum')
  tcp=ip[20:];pseudo=ip[12:20]+struct.pack('!BBH',0,6,len(tcp))
  if not valid_checksum(pseudo+tcp):raise ValueError('TCP checksum')
  frames.append({'frame':len(frames)+1,'epochMicros':t,'src':str(ipaddress.ip_address(ip[12:16])),'dst':str(ipaddress.ip_address(ip[16:20])),'tcpPayloadBytes':len(tcp)-((tcp[12]>>4)*4),'frameBytes':cap})
 if pos!=len(b) or len(frames)!=n:raise ValueError('Count or trailing bytes')
 return {'role':role,'sha256':h,'frames':len(frames),'filesystemBytes':len(b),'packetBytes':sum(f['frameBytes'] for f in frames),'rawRows':frames,'checksumAndFraming':'pass'}
if __name__=='__main__':
 try:print(json.dumps(check(sys.argv[1],sys.argv[2]),indent=2))
 except Exception as e:print(str(e),file=sys.stderr);sys.exit(1)
