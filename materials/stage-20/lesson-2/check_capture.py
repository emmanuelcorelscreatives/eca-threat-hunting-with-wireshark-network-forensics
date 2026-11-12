"""Read-only independent classic-PCAP checksum and record checker."""
import struct,sys,json,hashlib
from pathlib import Path
def checksum(data):
 if len(data)%2:data+=b'\0'
 total=sum(int.from_bytes(data[i:i+2],'big') for i in range(0,len(data),2))
 while total>>16:total=(total&65535)+(total>>16)
 return total==65535
reports=[]
for file in sys.argv[1:]:
 b=Path(file).read_bytes();assert b[:4]==bytes.fromhex('d4c3b2a1');assert struct.unpack_from('<I',b,20)[0]==1
 off=24;frames=[];last=-1
 while off<len(b):
  assert off+16<=len(b);sec,us,inc,orig=struct.unpack_from('<IIII',b,off);off+=16;packet=b[off:off+inc];off+=inc
  assert len(packet)==inc==orig and us<1000000 and sec*1000000+us>=last;last=sec*1000000+us
  assert packet[12:14]==b'\x08\x00';ip=packet[14:];assert ip[0]==69 and ip[9]==6 and int.from_bytes(ip[2:4],'big')==len(ip) and checksum(ip[:20])
  tcp=ip[20:];assert checksum(ip[12:20]+bytes([0,6])+len(tcp).to_bytes(2,'big')+tcp)
  frames.append({'frame':len(frames)+1,'epochMicroseconds':last,'source':'.'.join(map(str,ip[12:16])),'destination':'.'.join(map(str,ip[16:20])),'sourcePort':int.from_bytes(tcp[:2],'big'),'destinationPort':int.from_bytes(tcp[2:4],'big'),'flags':tcp[13],'payloadBytes':len(tcp)-(tcp[12]>>4)*4})
 assert off==len(b) and frames
 reports.append({'file':Path(file).name,'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'count':len(frames),'frames':frames})
print(json.dumps({'verdict':'pass','scope':'Actual record framing, monotonic timestamps, Ethernet IPv4 TCP lengths and IPv4/TCP checksums; no host identity or causal-chain verdict.','captures':reports},indent=2))
