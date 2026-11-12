#!/usr/bin/env python3
"""Read-only classic Ethernet/IPv4 TCP/DNS checker; does not import the fixture builder."""
import argparse,datetime,hashlib,json,socket,struct,re,collections
from pathlib import Path

def checksum(b):
 if len(b)%2:b+=b'\0'
 n=sum(struct.unpack('!%dH'%(len(b)//2),b))
 while n>>16:n=(n&65535)+(n>>16)
 return (~n)&65535

def dnsname(data,pos,visited=None):
 visited=set()if visited is None else visited;start=pos;labels=[];end=None
 while True:
  assert pos not in visited,'DNS compression loop';visited.add(pos);n=data[pos];pos+=1
  if n==0:return '.'.join(labels),end or pos
  if n&192==192:
   target=((n&63)<<8)|data[pos];pos+=1;part,_=dnsname(data,target,visited);labels.append(part);return '.'.join(labels),pos
  assert n<=63 and pos+n<=len(data),'DNS label bounds';labels.append(data[pos:pos+n].decode('ascii'));pos+=n

def check(capture,specfile):
 raw=capture.read_bytes();spec=json.loads(specfile.read_text());assert raw[:4]==b'\xd4\xc3\xb2\xa1','Only little-endian microsecond classic PCAP';assert struct.unpack_from('<I',raw,20)[0]==1,'Expected Ethernet';rows=[];offset=24
 while offset<len(raw):
  assert offset+16<=len(raw),'Record header truncated';sec,usec,cap,wire=struct.unpack_from('<IIII',raw,offset);offset+=16;assert cap==wire and offset+cap<=len(raw),'Truncated frame';pkt=raw[offset:offset+cap];offset+=cap;n=len(rows)+1;assert pkt[12:14]==b'\x08\x00','Expected IPv4';ip=pkt[14:];ihl=(ip[0]&15)*4;assert ip[0]>>4==4 and ihl>=20;total=struct.unpack_from('!H',ip,2)[0];assert total==len(ip),'IP length mismatch';assert checksum(ip[:ihl])==0,'Bad IP checksum';proto=ip[9];src=socket.inet_ntoa(ip[12:16]);dst=socket.inet_ntoa(ip[16:20]);payload=ip[ihl:];pseudo=ip[12:20]+bytes([0,proto])+struct.pack('!H',len(payload));e=spec['events'][n-1];dt=datetime.datetime.fromisoformat(e['timestamp'].replace('Z','+00:00'));expected_us=int(dt.timestamp())*1000000+dt.microsecond;assert sec*1000000+usec==expected_us,'Spec timestamp mismatch';assert e['src']==src and e['dst']==dst,'Spec address mismatch';r={'frame':n,'epochMicroseconds':sec*1000000+usec,'utc':datetime.datetime.fromtimestamp(sec,datetime.timezone.utc).replace(microsecond=usec).isoformat(),'frameBytes':cap,'src':src,'dst':dst,'ipChecksumValid':True}
  if proto==6:
   assert e['kind']=='tcp';sport,dport,seq,ack,offflags=struct.unpack_from('!HHIIH',payload);thl=(offflags>>12)*4;flags=offflags&511;assert thl>=20 and thl<=len(payload);tcpdata=payload[thl:];expected_flags=sum({'F':1,'S':2,'R':4,'P':8,'A':16,'U':32,'E':64,'C':128}[c]for c in e['flags']);assert (sport,dport,seq,ack,flags)==(e['sport'],e['dport'],e['seq'],e['ack'],expected_flags),'TCP fields disagree with spec';assert tcpdata==e.get('payloadText','').encode(),'TCP payload disagrees with spec';assert checksum(pseudo+payload)==0,'Bad TCP checksum';r.update(protocol='tcp',sport=sport,dport=dport,rawSeq=seq,rawAck=ack,flags=flags,tcpPayloadBytes=len(tcpdata),payloadHex=tcpdata.hex(),tcpChecksumValid=True)
  elif proto==17:
   assert e['kind']in['dns-query','dns-answer'];sport,dport,length,udpcheck=struct.unpack_from('!HHHH',payload);assert length==len(payload)and (sport,dport)==(e['sport'],e['dport']);assert udpcheck and checksum(pseudo+payload)==0,'UDP checksum absent/bad';dns=payload[8:];ident,flags,questions,answers,authority,additional=struct.unpack_from('!HHHHHH',dns);assert ident==e['transactionId']and questions==1 and authority==additional==0;name,pos=dnsname(dns,12);qtype,qclass=struct.unpack_from('!HH',dns,pos);pos+=4;assert name==e['name']and (qtype,qclass)==(1,1);assert flags==(0x100 if e['kind']=='dns-query'else 0x8180);assert answers==(0 if e['kind']=='dns-query'else 1);records=[]
   if answers:
    owner,pos=dnsname(dns,pos);typ,cls,ttl,size=struct.unpack_from('!HHIH',dns,pos);pos+=10;answer=socket.inet_ntoa(dns[pos:pos+size]);pos+=size;assert(owner,typ,cls,ttl,size,answer)==(e['name'],1,1,60,4,e['answer']);records.append({'owner':owner,'type':typ,'class':cls,'ttl':ttl,'address':answer})
   assert pos==len(dns),'Unexpected trailing DNS bytes';r.update(protocol='dns',sport=sport,dport=dport,dnsId=ident,dnsFlags=flags,question=name,answers=records,udpChecksumValid=True)
  else:raise AssertionError('Unsupported protocol')
  rows.append(r)
 assert len(rows)==len(spec['events'])and offset==len(raw),'Count/order/file-size mismatch';assert all(b['epochMicroseconds']>=a['epochMicroseconds']for a,b in zip(rows,rows[1:])),'Packet timestamps out of order'
 syn_seen={};starts=[];retries=[];ends=collections.defaultdict(set);ack_checks=[];streams=collections.defaultdict(list)
 for r in rows:
  if r['protocol']!='tcp':continue
  flow=(r['src'],r['sport'],r['dst'],r['dport']);reverse=(r['dst'],r['dport'],r['src'],r['sport']);end=(r['rawSeq']+r['tcpPayloadBytes']+bool(r['flags']&2)+bool(r['flags']&1))%2**32
  if r['flags']&16:
   ack_checks.append({'frame':r['frame'],'rawAck':r['rawAck'],'reverseTuple':list(reverse),'classification':'matches_observed_reverse_sequence_end'if r['rawAck']in ends[reverse]else'not_established_by_prior_observed_bytes','priorObservedSequenceEnds':sorted(ends[reverse])})
  ends[flow].add(end)
  if r['flags']&2 and not r['flags']&16:
   k=flow+(r['rawSeq'],)
   if k in syn_seen:retries.append({'frame':r['frame'],'firstFrame':syn_seen[k],'reason':'Same directional four-tuple and raw SYN sequence; within-file retry candidate, not another destination or purpose finding.'})
   else:syn_seen[k]=r['frame'];starts.append(r['frame'])
  if r['tcpPayloadBytes']:streams[flow].append(r)
 http=[]
 for flow,segments in streams.items():
  data={};origins={}
  for r in segments:
   for j,b in enumerate(bytes.fromhex(r['payloadHex'])):
    seq=r['rawSeq']+j
    if seq in data:assert data[seq]==b,'Conflicting TCP overlap'
    else:data[seq]=b;origins[seq]=r['frame']
  positions=sorted(data);chunks=[];start=None;last=None
  for seq in positions:
   if last is None or seq!=last+1:
    if start is not None:chunks.append((start,last+1))
    start=seq
   last=seq
  if start is not None:chunks.append((start,last+1))
  for left,right in chunks:
   buf=bytes(data[i]for i in range(left,right))
   for m in re.finditer(rb'(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) ([^\r\n ]+) HTTP/1\.[01]\r\n',buf):
    if m.start()and buf[max(0,m.start()-4):m.start()]!=b'\r\n\r\n':continue
    endhead=buf.find(b'\r\n\r\n',m.start());first=origins[left+m.start()];complete=origins[left+endhead+3]if endhead>=0 else None;http.append({'directionalTuple':list(flow),'method':m.group(1).decode(),'uri':m.group(2).decode(),'firstByteFrame':first,'firstByteEpochMicroseconds':rows[first-1]['epochMicroseconds'],'headerCompletionFrame':complete,'headerOriginFrames':sorted(set(origins[i]for i in range(left+m.start(),left+endhead+4)))if endhead>=0 else[],'scope':'Captured raw TCP byte origins, not a universal dissector classification or missing-byte inference.'})
 def intervals(frames):
  return[{'previousFrame':a,'frame':b,'deltaMicroseconds':rows[b-1]['epochMicroseconds']-rows[a-1]['epochMicroseconds']}for a,b in zip(frames,frames[1:])]
 special={}
 if spec.get('fixtureId')=='inter-arrival-timing-v1':
  accepted=[r['frame']for r in rows if r['frame']in starts and r['src']=='192.0.2.10'and r['dst']=='198.51.100.20'and r['dport']==80];requests=[r['firstByteFrame']for r in http if r['directionalTuple'][0]=='192.0.2.10'and r['directionalTuple'][2:] == ['198.51.100.20',80]];assert accepted==[3,20,24]and requests==[7,12];assert [r['deltaMicroseconds']for r in intervals(accepted)]==[60000000,60000000];assert [r['deltaMicroseconds']for r in intervals(requests)]==[20000000];assert next(r for r in http if r['uri']=='/a')['headerCompletionFrame']==8;special={'acceptedScopedSynFrames':accepted,'synIntervals':intervals(accepted),'acceptedScopedHttpFirstByteFrames':requests,'httpIntervals':intervals(requests),'rawByteFirstFrame7VersusHeaderCompleteFrame8Verified':True}
 return{'state':'COMPLETE','verdict':'pass','sourceCaptureSha256':hashlib.sha256(raw).hexdigest(),'specSha256':hashlib.sha256(specfile.read_bytes()).hexdigest(),'frameCount':len(rows),'physicalBytes':len(raw),'capturedPacketBytes':sum(r['frameBytes']for r in rows),'allFrameBytesAndTimestampOrderMatchActualSpec':True,'allIncludedIpv4AndTransportChecksumsValidatedFromRawBytes':True,'frames':rows,'distinctObservedSynStartFrames':starts,'sameTupleRawSynRetryCandidates':retries,'rawAckContinuityChecks':ack_checks,'httpCapturedByteOrigins':http,'lessonSpecificArithmetic':special,'limits':['Read-only parse of exact existing classicPCAP, no builder import or packet rewrite.','Spec agreement is distinct from real-world collection coverage, authorization, process or clock accuracy.','ACKs not established by prior captured reverse bytes remain explicitly unresolved; capture may start midstream.','Same-tuple same-sequence retry candidates and captured HTTP origins do not establish application purpose or unseen connection starts.']}

def main():
 a=argparse.ArgumentParser();a.add_argument('--capture',type=Path,required=True);a.add_argument('--spec',type=Path,required=True);args=a.parse_args();print(json.dumps(check(args.capture,args.spec),indent=2))
if __name__=='__main__':main()
