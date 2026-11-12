#!/usr/bin/env python3
"""Standard-library offline synthetic SMB2 lab builder. No sockets opened, no traffic sent."""
import argparse,datetime,ipaddress,json,pathlib,socket,struct

def checksum(b):
 b+=b'\0'*(len(b)%2);s=sum(struct.unpack('!%dH'%(len(b)//2),b));s=(s&65535)+(s>>16);s=(s&65535)+(s>>16);return ~s&65535

def packet(a,b,sp,dp,seq,ack,flags,payload=b''):
 src=socket.inet_aton(a);dst=socket.inet_aton(b)
 tcp=struct.pack('!HHIIBBHHH',sp,dp,seq,ack,80,flags,64240,0,0)+payload
 tcp=tcp[:16]+struct.pack('!H',checksum(src+dst+struct.pack('!BBH',0,6,len(tcp))+tcp))+tcp[18:]
 ip=struct.pack('!BBHHHBBH4s4s',69,0,20+len(tcp),1,16384,64,6,0,src,dst);ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
 return bytes.fromhex('0200000000020200000000010800')+ip+tcp

def smb(cmd,response,msg,peer,session):
 header=b'\xfeSMB'+struct.pack('<HHIHHIIQIIQ16s',64,0,0,cmd,1,int(response),0,msg,100,session if cmd==3 and response else 0,session if cmd==3 or cmd==1 and response else 0,b'\0'*16)
 if cmd==0:
  if response:body=struct.pack('<HHHH16sIIIIQQHHI',65,1,0x202,0,b'AcademyLabSMB2!!\0',0,65536,65536,65536,0,0,128,0,0)
  else:body=struct.pack('<HHHHI16sQH',36,1,1,0,0,b'AcademyClient!!\0\0',0,0x202)
 elif cmd==1:
  if response:body=struct.pack('<HHHH',9,1,72,0)
  else:body=struct.pack('<HBBIIHHQ',25,0,1,0,0,88,0,0)
 else:
  if response:body=struct.pack('<HBBIII',16,1,0,0,0,0x1f01ff)
  else:
   path=(chr(92)*2+peer+chr(92)+'AcademyLab').encode('utf-16le');body=struct.pack('<HHHH',9,0,72,len(path))+path
 p=header+body;return struct.pack('!I',len(p))+p

def build(spec,capture):
 records=[]
 for flow in spec['flows']:
  if flow['capture']!=capture:continue
  a,b=flow['client'],flow['peer'];assert all(ipaddress.ip_address(x) in ipaddress.ip_network('192.0.2.0/24') for x in (a,b))
  sp,dp=flow['clientPort'],flow['serverPort'];assert dp==445
  t=int(datetime.datetime.fromisoformat(flow['firstSmb2DesignUtc'].replace('Z','+00:00')).timestamp()*1000000);cs,ss=1000,9000
  rows=[(-100000,a,b,sp,dp,cs,0,2,b''),(-80000,b,a,dp,sp,ss,cs+1,18,b''),(-60000,a,b,sp,dp,cs+1,ss+1,16,b'')];cs+=1;ss+=1
  for index,cmd in enumerate((0,1,3)):
   req,resp=smb(cmd,False,index,b,sp),smb(cmd,True,index,b,sp)
   rows.append((index*40000,a,b,sp,dp,cs,ss,24,req));cs+=len(req)
   rows.append((index*40000+20000,b,a,dp,sp,ss,cs,24,resp));ss+=len(resp)
  rows.extend([(120000,a,b,sp,dp,cs,ss,16,b''),(140000,b,a,dp,sp,ss,cs,17,b''),(160000,a,b,sp,dp,cs,ss+1,16,b''),(180000,a,b,sp,dp,cs,ss+1,17,b''),(200000,b,a,dp,sp,ss+1,cs+1,16,b'')])
  for dt,*row in rows:records.append((t+dt,packet(*row)))
 records.sort(key=lambda x:x[0]);out=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
 for t,p in records:out+=struct.pack('<IIII',t//1000000,t%1000000,len(p),len(p))+p
 return out

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--scenario',required=True);ap.add_argument('--capture',choices=['practice.pcap','baseline-synthetic.pcap'],required=True);ap.add_argument('--output',required=True);args=ap.parse_args();spec=json.loads(pathlib.Path(args.scenario).read_text());assert spec['synthetic'] is True
 data=build(spec,args.capture)
 with pathlib.Path(args.output).open('xb') as f:f.write(data)
 print(json.dumps({'synthetic':True,'capture':args.capture,'bytes':len(data),'output':args.output}))
if __name__=='__main__':main()
