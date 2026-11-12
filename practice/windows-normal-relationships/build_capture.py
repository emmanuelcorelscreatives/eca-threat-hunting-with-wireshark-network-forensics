#!/usr/bin/env python3
"""Offline synthetic SMB2 Tree Connect fixture. No network or external modules."""
import struct,socket,datetime,sys,pathlib

def checksum(b):
 if len(b)%2:b+=b'\0'
 s=sum(struct.unpack('!%dH'%(len(b)//2),b));s=(s&65535)+(s>>16);s=(s&65535)+(s>>16);return (~s)&65535

def packet(a,b,sp,dp,seq,ack,flags,payload=b''):
 src=socket.inet_aton(a);dst=socket.inet_aton(b)
 tcp=struct.pack('!HHIIBBHHH',sp,dp,seq,ack,80,flags,64240,0,0)+payload
 c=checksum(src+dst+struct.pack('!BBH',0,6,len(tcp))+tcp);tcp=tcp[:16]+struct.pack('!H',c)+tcp[18:]
 ip=struct.pack('!BBHHHBBH4s4s',69,0,20+len(tcp),1,16384,64,6,0,src,dst);ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
 return bytes.fromhex('0200000000020200000000010800')+ip+tcp

def smb(response,share='',tree=0):
 header=b'\xfeSMB'+struct.pack('<HHIHHIIQIIQ16s',64,0,0,3,1,1 if response else 0,0,1,100,tree,1,b'\0'*16)
 if response:body=struct.pack('<HBBIII',16,1,0,0,0,0x1f01ff)
 else:
  path=share.encode('utf-16le');body=struct.pack('<HHHH',9,0,72,len(path))+path
 p=header+body;return struct.pack('!I',len(p))+p

def block(t,b):
 b+=b'\0'*((-len(b))%4);n=12+len(b);return struct.pack('<II',t,n)+b+struct.pack('<I',n)

def main():
 if len(sys.argv)!=2:raise SystemExit('Usage: python build_capture.py NEW_OUTPUT.pcapng')
 out=pathlib.Path(sys.argv[1]);records=[]
 for i,(a,b,share,minute) in enumerate([('192.0.2.21','192.0.2.40','TeamDocs',1),('192.0.2.70','192.0.2.21','ADMIN$',4),('192.0.2.21','192.0.2.22','ProjectDrop',7)]):
  port=50001+i;req=smb(False,'\\\\'+b+'\\'+share);resp=smb(True,tree=i+1)
  base=int(datetime.datetime(2025,1,16,12,minute,tzinfo=datetime.timezone.utc).timestamp()*1e6)
  rows=[(a,b,port,445,1000,0,2,b''),(b,a,445,port,5000,1001,18,b''),(a,b,port,445,1001,5001,16,b''),(a,b,port,445,1001,5001,24,req),(b,a,445,port,5001,1001+len(req),24,resp),(a,b,port,445,1001+len(req),5001+len(resp),16,b'')]
  for j,row in enumerate(rows):records.append((base+j*10000,packet(*row)))
 data=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))+block(1,struct.pack('<HHI',1,0,65535))
 for t,p in records:data+=block(6,struct.pack('<IIIII',0,t>>32,t&0xffffffff,len(p),len(p))+p)
 with out.open('xb') as f:f.write(data)
 print('Created',len(records),'synthetic packets;',len(data),'bytes')
if __name__=='__main__':main()
