#!/usr/bin/env python3
"""Build two fully synthetic Ethernet/IPv4/TCP teaching captures offline, never overwrite."""
import struct,socket,datetime,pathlib,sys

def checksum(b):
 if len(b)%2:b+=b'\0'
 s=sum(struct.unpack('!%dH'%(len(b)//2),b));s=(s&65535)+(s>>16);s=(s&65535)+(s>>16);return (~s)&65535

def packet(src,dst,sp,dp,seq,ack,flags,payload=b''):
 a=socket.inet_aton(src);b=socket.inet_aton(dst)
 tcp=struct.pack('!HHIIBBHHH',sp,dp,seq,ack,80,flags,65535,0,0)+payload
 c=checksum(a+b+struct.pack('!BBH',0,6,len(tcp))+tcp)
 tcp=tcp[:16]+struct.pack('!H',c)+tcp[18:]
 ip=struct.pack('!BBHHHBBH4s4s',69,0,20+len(tcp),0,16384,64,6,0,a,b)
 ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
 return bytes.fromhex('0200000000020200000000010800')+ip+tcp

def smb(response=False):
 header=b'\xfeSMB'+struct.pack('<HHIHHIIQIIQ',64,0,0,0,1,int(response),0,0,0,0,0)+bytes(16)
 if response:
  body=struct.pack('<HHHH16sIIIIQQHHI',65,1,0x202,0,bytes.fromhex('112233445566778899aabbccddeeff00'),0,65536,65536,65536,0,0,0,0,0)
 else:body=struct.pack('<HHHHI16sIHH',36,1,1,0,0,bytes.fromhex('00112233445566778899aabbccddeeff'),0,0,0)+struct.pack('<H',0x202)
 raw=header+body
 return struct.pack('!I',len(raw))+raw

def make(src,dst,sp,dp,base,p1,p2):
 frames=[]
 def add(t,rev,seq,ack,fl,data=b''):
  frames.append((base+t,packet(dst if rev else src,src if rev else dst,dp if rev else sp,sp if rev else dp,seq,ack,fl,data)))
 add(0,False,100,0,2);add(.1,True,700,101,18);add(.2,False,101,701,16)
 add(.25,False,101,701,24,p1);add(.3,True,701,101+len(p1),16);add(.35,True,701,101+len(p1),24,p2);add(.4,False,101+len(p1),701+len(p2),16)
 return frames

def main():
 out=pathlib.Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True)
 names=['OP-A-workstation-edge.pcap','OP-B-server-segment.pcap']
 if any((out/n).exists() for n in names):raise SystemExit('REFUSED: existing capture; choose an empty output directory')
 def ts(s):return datetime.datetime.fromisoformat(s).timestamp()
 groups=[make('192.0.2.23','198.51.100.14',49170,445,ts('2025-02-12T14:01:00+00:00'),smb(),smb(True)),make('198.51.100.14','198.51.100.15',49200,22,ts('2025-02-12T14:06:02+00:00'),b'SSH-2.0-LabClient_1.0\r\n',b'SSH-2.0-LabServer_1.0\r\n')]
 for name,frames in zip(names,groups):
  with (out/name).open('xb') as f:
   f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
   for t,p in frames:
    sec=int(t);micro=round((t-sec)*1e6);f.write(struct.pack('<IIII',sec,micro,len(p),len(p))+p)
if __name__=='__main__':main()
