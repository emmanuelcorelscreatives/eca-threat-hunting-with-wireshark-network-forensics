#!/usr/bin/env python3
"""Deterministic offline DNS Ethernet/IPv4/UDP training fixture. Never opens sockets."""
import sys,struct,socket,csv
from pathlib import Path

def name(s):return b''.join(bytes([len(p)])+p.encode('ascii') for p in s.rstrip('.').split('.'))+b'\0'
def checksum(b):
 if len(b)%2:b+=b'\0'
 s=sum(struct.unpack('!%dH'%(len(b)//2),b));s=(s>>16)+(s&65535);s+=(s>>16);return (~s)&65535

def build(cards):
 out=bytearray(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)); frame=0
 for i,r in enumerate(csv.DictReader(open(cards,newline='')),1):
  typ={'A':1,'PTR':12,'TXT':16,'SRV':33}[r['modeled_qtype']]; question=name(r['modeled_name'])+struct.pack('!HH',typ,1)
  src={'D':'192.0.2.10','F':'192.0.2.20','U':'192.0.2.30'}[r['case_id']]; resolver='192.0.2.53'; offset=float(r['offset_seconds'])
  for response in ([False] if r['modeled_response']=='NO_VISIBLE_RESPONSE' else [False,True]):
   answer=b''; nx=r['modeled_response']=='NXDOMAIN'
   if response and not nx:
    value=r['modeled_answer']
    if typ==1:data=socket.inet_aton(value)
    elif typ==12:data=name(value)
    elif typ==33:
     host,port=value.rsplit(':',1); data=struct.pack('!HHH',0,0,int(port))+name(host)
    else:data=bytes([len(value)])+value.encode('ascii')
    answer=b'\xc0\x0c'+struct.pack('!HHIH',typ,1,60,len(data))+data
   dns=struct.pack('!HHHHHH',0x4000+i,(0x8183 if nx else 0x8180) if response else 0x0100,1,int(bool(answer)),0,0)+question+answer
   source,dest=(resolver,src) if response else (src,resolver);sp,dp=(53,53000+i) if response else (53000+i,53)
   udp=struct.pack('!HHHH',sp,dp,len(dns)+8,0)+dns
   pseudo=socket.inet_aton(source)+socket.inet_aton(dest)+struct.pack('!BBH',0,17,len(udp));uc=checksum(pseudo+udp) or 65535
   udp=udp[:6]+struct.pack('!H',uc)+udp[8:]; frame+=1
   ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),frame,0,64,17,0,socket.inet_aton(source),socket.inet_aton(dest));ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
   eth=bytes.fromhex('0200000000530200000000100800')+ip+udp
   ts=1762905600+offset+(.05 if response else 0); sec=int(ts);usec=round((ts-sec)*1000000)
   out.extend(struct.pack('<IIII',sec,usec,len(eth),len(eth))+eth)
 return bytes(out)
if __name__=='__main__':
 if len(sys.argv)!=3:raise SystemExit('Usage: offline-builder.py scenario-cards.csv NEW_OUTPUT.pcap')
 data=build(sys.argv[1])
 with open(sys.argv[2],'xb') as f:f.write(data)
 print('Wrote',len(data),'bytes; no network access')
