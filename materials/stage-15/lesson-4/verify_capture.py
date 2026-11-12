#!/usr/bin/env python3
"""Independent raw parser with strict structure, checksum and reference validation."""
import argparse,struct,json,socket,base64,hashlib,datetime
from pathlib import Path
def checksum(b):
 b+=b'\0'*(len(b)%2);t=sum((b[i]<<8)|b[i+1] for i in range(0,len(b),2))
 while t>65535:t=(t&65535)+(t>>16)
 return t==65535
def verify(b,m):
 assert len(b)>=24 and struct.unpack('<IHHIIII',b[:24])==(0xa1b2c3d4,2,4,0,0,65535,1),'PCAP header';pos=24;rows=[];d=m['dns'];name=b''.join(bytes([len(s)])+s.encode() for s in d['name'].split('.'))+b'\0';question=name+struct.pack('!HH',16,1)
 for i in range(2):
  assert pos+16<=len(b),'record header';sec,usec,cap,orig=struct.unpack('<IIII',b[pos:pos+16]);pos+=16;f=b[pos:pos+cap];pos+=cap;assert len(f)==cap==orig,'record length';assert f[:14]==bytes.fromhex('0200000000020200000000010800'),'Ethernet';ip=f[14:34];assert ip[0]==0x45 and ip[9]==17 and int.from_bytes(ip[2:4],'big')==len(f)-14 and checksum(ip),'IPv4';assert ip[6:8]==b'\0\0','fragment';src=socket.inet_ntoa(ip[12:16]);dst=socket.inet_ntoa(ip[16:20]);assert (src,dst)==((d['clientIp'],d['resolverIp']) if i==0 else (d['resolverIp'],d['clientIp'])),'direction';u=f[34:];sp,dp,ln,cs=struct.unpack('!HHHH',u[:8]);assert ln==len(u) and cs and checksum(ip[12:20]+struct.pack('!BBH',0,17,ln)+u),'UDP';assert (sp,dp)==((d['clientPort'],53) if i==0 else (53,d['clientPort'])),'ports';dns=u[8:];assert struct.unpack('!HHHHHH',dns[:12])==(d['transactionId'],0x100 if i==0 else 0x8180,1,i,0,0),'DNS header';assert dns[12:12+len(question)]==question,'question';tail=dns[12+len(question):];t=datetime.datetime.fromisoformat(d['queryUtc' if i==0 else 'responseUtc'].replace('Z','+00:00'));assert (sec,usec)==(int(t.timestamp()),t.microsecond),'timestamp';row={'frame':i+1,'source':src,'destination':dst,'sourcePort':sp,'destinationPort':dp,'utc':t.isoformat(),'frameBytes':len(f),'response':bool(i)}
  if i:
   v=m['marker']['intendedTxtValue'].encode();expected=b'\xc0\x0c'+struct.pack('!HHIH',16,1,d['answerTtlSeconds'],len(v)+1)+bytes([len(v)])+v;assert tail==expected,'TXT answer';decoded=base64.b64decode(v,validate=True);assert decoded.hex()==m['marker']['utf8Hex'] and decoded.decode()==m['marker']['label'],'reference';offset=42+12+len(question)+13;assert f[offset:offset+len(v)]==v;row.update(txtContentOffsetZeroBased=offset,txtContentEndInclusive=offset+len(v)-1,txtContentHex=v.hex(),decodedHex=decoded.hex(),decodedText=decoded.decode(),excludedLengthByteOffset=offset-1)
  else:assert not tail,'query trailing bytes'
  rows.append(row)
 assert pos==len(b),'trailing file bytes'
 return {'verdict':'pass','sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'packetCount':len(rows),'rows':rows,'scope':'Independent standard-library raw parser of synthetic author fixture; no live collection or GUI claim'}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--capture',required=True);p.add_argument('--reference',default='marker.json');a=p.parse_args();print(json.dumps(verify(Path(a.capture).read_bytes(),json.loads(Path(a.reference).read_text())),indent=2))
