"""Offline synthetic packet builder. No sockets; refuses any existing output directory."""
import struct,socket,sys
from pathlib import Path
out=Path(sys.argv[1]);out.mkdir(exist_ok=False)
def ck(b):
 if len(b)%2:b+=b'\0'
 s=sum(struct.unpack('!%dH'%(len(b)//2),b));s=(s&65535)+(s>>16);s=(s&65535)+(s>>16);return (~s)&65535
def pkt(a,b,sp,dp,seq,ack,flags,data=b''):
 aa=socket.inet_aton(a);bb=socket.inet_aton(b);t=struct.pack('!HHIIBBHHH',sp,dp,seq,ack,80,flags,8192,0,0)+data
 t=t[:16]+struct.pack('!H',ck(aa+bb+struct.pack('!BBH',0,6,len(t))+t))+t[18:]
 ip=struct.pack('!BBHHHBBH4s4s',69,0,20+len(t),1,0,64,6,0,aa,bb);ip=ip[:10]+struct.pack('!H',ck(ip))+ip[12:]
 return bytes.fromhex('0200000000020200000000010800')+ip+t
def conn(rows,tm,a,b,sp,dp,client=b'',server=b''):
 rows.extend([(tm,pkt(a,b,sp,dp,100,0,2)),(tm+.01,pkt(b,a,dp,sp,200,101,18)),(tm+.02,pkt(a,b,sp,dp,101,201,16))])
 if client:rows.append((tm+.03,pkt(a,b,sp,dp,101,201,24,client)))
 if server:rows.append((tm+.04,pkt(b,a,dp,sp,201,101+len(client),24,server)))
 rows.append((tm+.05,pkt(a,b,sp,dp,101+len(client),201+len(server),16)))
rows=[];conn(rows,1700000000,'192.0.2.10','198.51.100.20',51000,80,b'GET /training.txt HTTP/1.1\r\nHost: delivery.example\r\n\r\n',b'HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\ntraining only')
sets={'delivery.pcap':rows};rows=[]
for i,t in enumerate([1700000060,1700000120,1700000180]):conn(rows,t,'192.0.2.10','203.0.113.40',52000+i,443,b'opaque-example')
for i,t in enumerate([1700000065,1700000125,1700000185]):conn(rows,t,'192.0.2.10','203.0.113.80',53000+i,443,b'updater-example')
sets['outbound.pcap']=sorted(rows,key=lambda x:x[0]);rows=[];conn(rows,1700000200,'192.0.2.10','192.0.2.50',54000,22,server=b'SSH-2.0-AcademyFixture\r\n');sets['internal.pcap']=rows
for name,rows in sets.items():
 with (out/name).open('xb') as f:
  f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
  for tm,b in rows:
   sec=int(tm);us=round((tm-sec)*1000000);f.write(struct.pack('<IIII',sec,us,len(b),len(b)));f.write(b)
