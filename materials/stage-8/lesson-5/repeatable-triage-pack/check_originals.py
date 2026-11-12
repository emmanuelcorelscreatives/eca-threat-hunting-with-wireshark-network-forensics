#!/usr/bin/env python3
"""Read actual PCAP records independently of the builder; send no traffic."""
from pathlib import Path
import json,struct,hashlib,datetime as dt,csv

def good(b):
 if len(b)%2:b+=b'\0'
 s=sum(struct.unpack('!%dH'%(len(b)//2),b))
 while s>>16:s=(s&65535)+(s>>16)
 return s==65535
results=[]
for id,count in [('point-a',7),('point-b',3),('point-c',4)]:
 p=Path('inputs/originals')/(id+'.pcap');b=p.read_bytes();assert b[:4]==b'\xd4\xc3\xb2\xa1';off=24;frames=[]
 while off<len(b):
  sec,mic,inc,orig=struct.unpack_from('<IIII',b,off);off+=16;f=b[off:off+inc];off+=inc;assert inc==orig==len(f);assert f[12:14]==b'\x08\x00';ip=f[14:];hl=(ip[0]&15)*4;total=struct.unpack_from('!H',ip,2)[0];assert total==len(ip)and good(ip[:hl]);assert ip[9]==6;tcp=ip[hl:];assert good(ip[12:20]+struct.pack('!BBH',0,6,len(tcp))+tcp);th=(tcp[12]>>4)*4
  frames.append({'frame':len(frames)+1,'epoch':str(sec)+'.'+str(mic).zfill(6),'frameLength':len(f),'ipId':struct.unpack_from('!H',ip,4)[0],'src':'.'.join(map(str,ip[12:16])),'dst':'.'.join(map(str,ip[16:20])),'seqRaw':struct.unpack_from('!I',tcp,4)[0],'ackRaw':struct.unpack_from('!I',tcp,8)[0],'tcpPayloadBytes':len(tcp)-th,'payload':tcp[th:].decode()})
 assert off==len(b)and len(frames)==count
 results.append({'source':id,'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'frames':frames,'allIPv4AndTCPChecksumsValid':True})
a,b,c=[r['frames']for r in results];assert a[3]['tcpPayloadBytes']==51 and a[4]['ackRaw']==1052;assert a[4]['tcpPayloadBytes']==40
assert b[2]['epoch']==c[0]['epoch']==a[3]['epoch']and b[2]['payload']==c[0]['payload']==a[3]['payload']
assert [a[3]['ipId'],b[2]['ipId'],c[0]['ipId']]==[4,3,1]
# Source-local frame references remain distinct: equal payload/time is not byte identity.
print(json.dumps({'independentRawParser':True,'builderImported':False,'sources':results,'requestOriginalFrames':{'point-a':4,'point-b':3,'point-c':1},'matchingEventHasDifferentIPv4Ids':True,'clockSynchronizationEstablished':False},indent=2))
