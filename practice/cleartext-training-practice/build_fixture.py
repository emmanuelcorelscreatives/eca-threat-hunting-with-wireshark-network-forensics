#!/usr/bin/env python3
"""Build only this labelled synthetic offline training PCAP, without sockets or dependencies."""
import argparse,struct,socket,pathlib

def checksum(b):
 if len(b)%2:b+=b'\0'
 n=sum(struct.unpack('!%dH'%(len(b)//2),b));n=(n&65535)+(n>>16);n=(n&65535)+(n>>16);return (~n)&65535

def build():
 packets=[]
 def packet(src,dst,sp,dp,seq,ack,flags,payload=b''):
  a,b=socket.inet_aton(src),socket.inet_aton(dst); tcp=struct.pack('!HHIIBBHHH',sp,dp,seq,ack,80,flags,32768,0,0)+payload
  c=checksum(a+b+struct.pack('!BBH',0,6,len(tcp))+tcp);tcp=tcp[:16]+struct.pack('!H',c)+tcp[18:]
  ip=struct.pack('!BBHHHBBH4s4s',69,0,20+len(tcp),len(packets)+1,16384,64,6,0,a,b);ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
  packets.append(bytes.fromhex('0200000000020200000000010800')+ip+tcp)
 def session(port,clientport,exchanges):
  c,s='192.0.2.10','198.51.100.20'; cs,ss=1000,9000
  packet(c,s,clientport,port,cs,0,2);packet(s,c,port,clientport,ss,cs+1,18);cs+=1;ss+=1;packet(c,s,clientport,port,cs,ss,16)
  for direction,payload in exchanges:
   if direction=='c':packet(c,s,clientport,port,cs,ss,24,payload);cs+=len(payload);packet(s,c,port,clientport,ss,cs,16)
   else:packet(s,c,port,clientport,ss,cs,24,payload);ss+=len(payload);packet(c,s,clientport,port,cs,ss,16)
  packet(c,s,clientport,port,cs,ss,17);cs+=1;packet(s,c,port,clientport,ss,cs,17);ss+=1;packet(c,s,clientport,port,cs,ss,16)
 session(21,41000,[('s',b'220 Academy isolated training fixture\r\n'),('c',b'USER synthetic_student\r\n'),('s',b'331 Synthetic password required\r\n'),('c',b'PASS synthetic_only_never_valid\r\n'),('s',b'230 Synthetic login accepted\r\n')])
 session(21,41001,[('s',b'220 Academy isolated training fixture\r\n'),('c',b'USER synthetic_rejected\r\n'),('s',b'331 Synthetic password required\r\n'),('c',b'PASS synthetic_only_rejected\r\n'),('s',b'530 Synthetic login rejected\r\n')])
 session(80,42000,[('c',b'GET /training HTTP/1.1\r\nHost: cleartext.example.invalid\r\nAuthorization: Basic c3ludGhldGljOnRyYWluaW5nX29ubHk=\r\nConnection: close\r\n\r\n'),('s',b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')])
 session(80,42001,[('c',b'GET /marker HTTP/1.1\r\nHost: cleartext.example.invalid\r\nX-Training-Marker: PASS is a word, not an FTP command\r\nConnection: close\r\n\r\n'),('s',b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')])
 out=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
 for i,p in enumerate(packets):out+=struct.pack('<IIII',1767225600+i//10,(i%10)*100000,len(p),len(p))+p
 return out
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
 with a.output.open('xb') as f:f.write(build())
