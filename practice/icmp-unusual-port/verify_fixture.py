#!/usr/bin/env python3
"""Independently inspect fixture bytes. Offline, standard library only."""
import argparse,struct,json,hashlib,ipaddress,datetime
from pathlib import Path

def checksum(b):
 if len(b)%2:b+=b'\0'
 n=sum(int.from_bytes(b[i:i+2],'big') for i in range(0,len(b),2))
 while n>>16:n=(n&65535)+(n>>16)
 return n

def main():
 p=argparse.ArgumentParser();p.add_argument('--spec',required=True,type=Path);p.add_argument('--pcap',required=True,type=Path);a=p.parse_args();b=a.pcap.read_bytes();s=json.loads(a.spec.read_text());assert struct.unpack('<IHHIIII',b[:24])==(0xa1b2c3d4,2,4,0,0,65535,1)
 offset=24;packets=[];rows=[]
 for i,e in enumerate(s['events'],1):
  sec,micro,cap,orig=struct.unpack_from('<IIII',b,offset);offset+=16;packet=b[offset:offset+cap];offset+=cap;assert cap==orig==len(packet)
  want=datetime.datetime.fromisoformat(e['timestamp'].replace('Z','+00:00'));assert sec*1000000+micro==int(want.timestamp())*1000000+want.microsecond
  ip=packet[14:];version=ip[0]>>4
  if version==4:
   assert ip[0]==69 and checksum(ip[:20])==65535 and int.from_bytes(ip[2:4],'big')==len(ip)
   src,dst=map(lambda q:str(ipaddress.ip_address(q)),(ip[12:16],ip[16:20]));proto=ip[9];body=ip[20:]
   pseudo=ip[12:20]+bytes([0,proto])+len(body).to_bytes(2,'big')
  else:
   assert version==6 and int.from_bytes(ip[4:6],'big')==len(ip)-40
   src,dst=map(lambda q:str(ipaddress.ip_address(q)),(ip[8:24],ip[24:40]));proto=ip[6];body=ip[40:];pseudo=ip[8:40]+struct.pack('!I3xB',len(body),proto)
  assert (src,dst)==(e['src'],e['dst'])
  if proto==6:
   assert checksum(pseudo+body)==65535 and struct.unpack('!HH',body[:4])==(e['sport'],e['dport']);assert body[20:]==e['payloadText'].encode()
   assert struct.unpack('!II',body[4:12])==(e['seq'],e['ack'])
  elif proto==17:
   assert checksum(pseudo+body)==65535 and struct.unpack('!HH',body[:4])==(e['sport'],e['dport']);assert int.from_bytes(body[4:6],'big')==len(body) and body[8:]==e['payloadText'].encode()
  elif proto in (1,58):
   assert checksum((pseudo if proto==58 else b'')+body)==65535
   if e['kind']=='icmp-error':
    assert body[:2]==b'\x03\x03' and body[8:]==packets[32][14:42], 'Quote must equal actual frame33 IPv4 header plus UDP header'
   else:
    assert body[0]=={'icmp-echo':8,'icmp-reply':0,'icmpv6-echo':128,'icmpv6-reply':129}[e['kind']]
    assert struct.unpack('!HH',body[4:8])==(e['identifier'],e['sequence']) and body[8:]==e['payloadText'].encode()
    if e['kind'] in ('icmp-reply','icmpv6-reply'):assert body[4:]==(packets[-1][34:] if proto==1 else packets[-1][54:])[4:]
  else:raise AssertionError('Unexpected protocol')
  packets.append(packet);rows.append({'frame':i,'kind':e['kind'],'bytes':len(packet),'checksums':'valid'})
 assert offset==len(b) and len(packets)==34
 print(json.dumps({'verdict':'pass','frames':34,'filesystemBytes':len(b),'packetBytes':sum(map(len,packets)),'sha256':hashlib.sha256(b).hexdigest(),'checks':rows,'independentOfBuilder':True},indent=2))
if __name__=='__main__':main()
