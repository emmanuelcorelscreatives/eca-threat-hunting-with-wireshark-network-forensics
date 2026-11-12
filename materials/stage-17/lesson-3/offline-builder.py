#!/usr/bin/env python3
"""Standard-library deterministic synthetic SMB2 packet fixture; never opens a socket.
Empty security blobs model accepted sessions, not realistic authentication evidence.
"""
import struct as s,socket,hashlib,json,sys,pathlib,datetime
P=lambda fmt,*v:s.pack('<'+fmt,*v)
records=[]
def checksum(b):
 if len(b)%2:b+=b'\0'
 n=sum(s.unpack('!%dH'%(len(b)//2),b));n=(n>>16)+(n&65535);n+=(n>>16);return (~n)&65535

def packet(src,dst,sp,dp,seq,ack,flags,payload=b''):
 a=socket.inet_aton(src);b=socket.inet_aton(dst)
 tcp=s.pack('!HHIIBBHHH',sp,dp,seq,ack,80,flags,65535,0,0)+payload
 c=checksum(a+b+s.pack('!BBH',0,6,len(tcp))+tcp);tcp=tcp[:16]+s.pack('!H',c)+tcp[18:]
 ip=s.pack('!BBHHHBBH4s4s',69,0,20+len(tcp),len(records)+1,16384,64,6,0,a,b);ip=ip[:10]+s.pack('!H',checksum(ip))+ip[12:]
 return bytes.fromhex('0200000000020200000000010800')+ip+tcp

def smb(cmd,mid,session,tree,response,body):
 h=b'\xfeSMB'+P('HHIHHIIQIIQ',64,1,0,cmd,1,1 if response else 0,0,mid,1234,tree,session)+b'\0'*16
 assert len(h)==64
 x=h+body;return s.pack('!I',len(x))+x

def block(t,b):
 b+=b'\0'*((-len(b))%4);n=len(b)+12;return P('II',t,n)+b+P('I',n)
def option(t,b):return P('HH',t,len(b))+b+b'\0'*((-len(b))%4)

def build():
 global records
 records=[]
 for client,port,base,session,tree,full in [('192.0.2.11',50101,1739178300,700,70,False),('192.0.2.10',50102,1739181600,900,90,True)]:
  server='198.51.100.20';cs,ss=1000,9000
  def emit(reverse,flags,data=b'',dt=0):
   nonlocal cs,ss
   if reverse:pkt=packet(server,client,445,port,ss,cs,flags,data);ss+=len(data)+(bool(flags&3))
   else:pkt=packet(client,server,port,445,cs,ss if flags!=2 else 0,flags,data);cs+=len(data)+(bool(flags&3))
   records.append((int((base+dt)*1000000),pkt))
  emit(False,2,dt=0);emit(True,18,dt=.001);emit(False,16,dt=.002)
  # Negotiation SMB2.0.2, unsigned and unencrypted, explicitly synthetic.
  req=P('HHHHI',36,1,1,0,0)+b'\x33'*16+P('IHHH',0,0,0,0x202)
  resp=P('HHHH',65,1,0x202,0)+b'\x44'*16+P('IIIIQQHHI',0,65536,65536,65536,0,0,0,0,0)
  for reverse,body in [(False,req),(True,resp)]:emit(reverse,24,smb(0,0,0,0,reverse,body),.01+.01*reverse)
  req=P('HBBIIHHQ',25,0,1,0,0,88,0,0);resp=P('HHHH',9,0,72,0)
  for reverse,body in [(False,req),(True,resp)]:emit(reverse,24,smb(1,1,session if reverse else 0,0,reverse,body),.1+.02*reverse)
  path=('\\\\198.51.100.20\\ADMIN$').encode('utf-16le')
  req=P('HHHH',9,0,72,len(path))+path;resp=P('HBBIII',16,1,0,0,0,0x1f01ff)
  for reverse,body in [(False,req),(True,resp)]:emit(reverse,24,smb(3,2,session,tree if reverse else 0,reverse,body),.2+.02*reverse)
  if full:
   fid=bytes.fromhex('11111111111111112222222222222222');name='eca-training-marker.txt'.encode('utf-16le')
   req=P('HBBIQQIIIIIHHII',57,0,0,2,0,0,0x12019f,0x80,7,3,0,120,len(name),0,0)+name
   resp=P('HBBIQQQQQQII',89,0,0,1,0,0,0,0,0,0,0x80,0)+fid+P('II',0,0)
   for reverse,body in [(False,req),(True,resp)]:emit(reverse,24,smb(5,3,session,tree,reverse,body),.3+.02*reverse)
   req=P('HHIQ',49,112,4,0)+fid+P('IIHHI',0,0,0,0,0)+b'ECA!';resp=P('HHIIHH',17,0,4,0,0,0)
   for reverse,body in [(False,req),(True,resp)]:emit(reverse,24,smb(9,4,session,tree,reverse,body),.4+.02*reverse)
   req=P('HHI',24,0,0)+fid;resp=P('HHIQQQQQQI',60,0,0,0,0,0,0,0,0,0x80)
   for reverse,body in [(False,req),(True,resp)]:emit(reverse,24,smb(6,5,session,tree,reverse,body),.5+.02*reverse)
  emit(False,17,dt=.7);emit(True,17,dt=.701);emit(False,16,dt=.702)
 shb=block(0x0a0d0d0a,P('IHHq',0x1a2b3c4d,1,0,-1)+option(1,b'Academy offline synthetic SMB2; no live collection; full authored TCP boundaries; no real authentication')+P('HH',0,0))
 idb=block(1,P('HHI',1,0,65535)+option(2,b'authored-offline-link')+option(3,b'Logical bidirectional synthetic Ethernet; not a physical observation point')+option(9,b'\x06')+P('HH',0,0))
 return shb+idb+b''.join(block(6,P('IIIII',0,t>>32,t&0xffffffff,len(p),len(p))+p)for t,p in records)
if __name__=='__main__':
 dest=pathlib.Path(sys.argv[1] if len(sys.argv)>1 else 'admin-share-training.pcapng');b=build()
 with dest.open('xb') as f:f.write(b)
 print(json.dumps({'file':str(dest),'frames':len(records),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'networkOperations':0}))
