#!/usr/bin/env python3
"""Independently parse PCAP, checksums, TCP continuity, SMB2 direction/commands and scenario times offline."""
import argparse,datetime,json,pathlib,socket,struct
from build_fixture import checksum

def check(path,scenario):
 b=path.read_bytes();assert b[:4]==bytes.fromhex('d4c3b2a1');offset=24;rows=[];states={};smbs=[]
 while offset<len(b):
  sec,usec,n,orig=struct.unpack_from('<IIII',b,offset);offset+=16;frame=b[offset:offset+n];offset+=n;assert n==orig and len(frame)==n
  ip=frame[14:];assert ip[0]==69 and struct.unpack('!H',ip[2:4])[0]==len(ip) and checksum(ip[:20])==0
  tcp=ip[20:];assert checksum(ip[12:20]+struct.pack('!BBH',0,6,len(tcp))+tcp)==0
  a,c=socket.inet_ntoa(ip[12:16]),socket.inet_ntoa(ip[16:20]);sp,dp,seq,ack=struct.unpack_from('!HHII',tcp);flags=tcp[13];data=tcp[(tcp[12]>>4)*4:];key=(a,sp,c,dp);reverse=(c,dp,a,sp)
  assert key not in states or seq==states[key],('sequence',key,seq,states.get(key))
  if flags&16:assert reverse in states and ack==states[reverse],('ack',key,ack,states.get(reverse))
  states[key]=seq+len(data)+bool(flags&2)+bool(flags&1);number=len(rows)+1
  row={'frame':number,'epochMicroseconds':sec*1000000+usec,'source':a,'destination':c,'sourcePort':sp,'destinationPort':dp,'seq':seq,'ack':ack,'flags':flags,'payloadBytes':len(data)}
  if data:
   assert struct.unpack('!I',data[:4])[0]==len(data)-4 and data[4:8]==b'\xfeSMB'
   command=struct.unpack_from('<H',data,16)[0];response=bool(struct.unpack_from('<I',data,20)[0]&1);assert command in (0,1,3)
   row.update(smb2Command=command,response=response)
   if response:assert struct.unpack_from('<I',data,12)[0]==0
   if command==3 and not response:
    pos,length=struct.unpack_from('<HH',data,72+0);row['share']=data[4+pos:4+pos+length].decode('utf-16le');assert row['share']==chr(92)*2+c+chr(92)+'AcademyLab',row
   smbs.append(row)
  rows.append(row)
 assert offset==len(b)
 flows=[f for f in scenario['flows'] if f['capture']==path.name];assert len(rows)==len(flows)*14 and len(smbs)==len(flows)*6
 for flow in flows:
  match=[x for x in smbs if x['source']==flow['client'] and x['destination']==flow['peer'] and x['sourcePort']==flow['clientPort']];assert len(match)==3 and [x['smb2Command'] for x in match]==[0,1,3]
  t=int(datetime.datetime.fromisoformat(flow['firstSmb2DesignUtc'].replace('Z','+00:00')).timestamp()*1000000);assert match[0]['epochMicroseconds']==t
 return {'capture':path.name,'packetCount':len(rows),'smb2Frames':len(smbs),'allChecksumsValid':True,'tcpSequenceAckContinuity':True,'firstSmb2Requests':[x for x in smbs if x['smb2Command']==0 and not x['response']],'rows':rows}
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--scenario',required=True);ap.add_argument('--capture',required=True);args=ap.parse_args();print(json.dumps(check(pathlib.Path(args.capture),json.loads(pathlib.Path(args.scenario).read_text())),indent=2))
