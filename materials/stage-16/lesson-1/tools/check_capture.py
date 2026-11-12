#!/usr/bin/env python3
"""Independent raw classic-PCAP and TShark verifier; never opens a network socket."""
import argparse, pathlib, struct, json, hashlib, subprocess, csv, io, socket, datetime

def check(path,scenario,tshark):
 b=pathlib.Path(path).read_bytes();d=json.loads(pathlib.Path(scenario).read_text());assert b[:4]==bytes.fromhex('d4c3b2a1');assert struct.unpack_from('<I',b,20)[0]==1
 pos=24;frames=[]
 def valid_checksum(data):
  if len(data)%2:data+=b'\0'
  n=sum(struct.unpack('!%dH'%(len(data)//2),data));n=(n&65535)+(n>>16);n=(n&65535)+(n>>16);return n==65535
 while pos<len(b):
  sec,usec,n,orig=struct.unpack_from('<IIII',b,pos);pos+=16;raw=b[pos:pos+n];pos+=n;assert len(raw)==n==orig;assert raw[12:14]==b'\x08\x00';ip=raw[14:];ihl=(ip[0]&15)*4;assert valid_checksum(ip[:ihl]);assert len(ip)==struct.unpack_from('!H',ip,2)[0];segment=ip[ihl:];proto=ip[9];assert proto in (6,17);assert valid_checksum(ip[12:20]+struct.pack('!BBH',0,proto,len(segment))+segment);frames.append((sec*1000000+usec,ip,segment))
 assert pos==len(b) and len(frames)==24
 assert [t for t,_,_ in frames]==sorted(t for t,_,_ in frames)
 assert frames[0][0]==1739354430000000 and frames[-1][0]==1739355005040000
 fields=['dns.id','dns.qry.name','dns.qry.type','dns.qry.class','dns.flags.response','dns.resp.ttl','udp.srcport','udp.dstport','dns.count.answers','frame.number','frame.time_epoch','ip.src','ip.dst','tcp.stream','tcp.srcport','tcp.dstport','tcp.flags','tcp.seq_raw','tcp.ack_raw','tcp.len','dns.a','http.host','tcp.analysis.retransmission']
 args=[tshark,'-r',path,'-T','fields','-E','header=y','-E','separator=\t','-E','occurrence=a']
 for f in fields:args+=['-e',f]
 r=subprocess.run(args,check=True,capture_output=True,text=True);rows=list(csv.DictReader(io.StringIO(r.stdout),delimiter='\t'));assert len(rows)==24
 dns=d['dnsDesign'];roles=d['roles']
 for ix,response in [(0,False),(1,True)]:
  row=rows[ix];t,ip,seg=frames[ix]
  assert ip[9]==17 and socket.inet_ntoa(ip[12:16])==roles['resolver' if response else 'client'] and socket.inet_ntoa(ip[16:20])==roles['client' if response else 'resolver']
  assert int(row['dns.id'],16)==dns['transactionId'] and row['dns.qry.name']==dns['name'] and row['dns.qry.type']=='1' and int(row['dns.qry.class'],16)==1
  assert row['dns.flags.response']==('True' if response else 'False') and int(row['dns.count.answers'])==(2 if response else 0)
  assert (int(row['udp.srcport']),int(row['udp.dstport']))==((53,dns['clientPort']) if response else (dns['clientPort'],53))
  expected_time=int(datetime.datetime.fromisoformat(dns['responseUtc' if response else 'queryUtc'].replace('Z','+00:00')).timestamp()*1000000);assert t==expected_time
 assert rows[1]['dns.a']==','.join(roles[x] for x in dns['answers']) and rows[1]['dns.resp.ttl']==','.join([str(dns['ttlSeconds'])]*2)
 assert rows[12]['http.host']=='relay.academy.test' and rows[12]['tcp.len']=='50' and rows[14]['tcp.len']=='40'
 assert rows[20]['tcp.analysis.retransmission']=='1' and rows[19]['tcp.stream']==rows[20]['tcp.stream']=='3'
 assert [int(x['frame.number']) for x in rows if float(x['frame.time_epoch'])>=1739354400 and float(x['frame.time_epoch'])<1739355000]==list(range(1,22))
 for i,ip,seg in frames:
  assert socket.inet_ntoa(ip[12:16]) in d['roles'].values() and socket.inet_ntoa(ip[16:20]) in d['roles'].values()
 # Compare every designed TCP sequence, acknowledgment, flags and payload, independently of builder.
 expected=[]
 for s in d['sessionDesigns']:
  for e in s['packetPlan']:
   us=int(datetime.datetime.fromisoformat(s['startUtc'].replace('Z','+00:00')).timestamp()*1000000)+e['offsetMs']*1000
   forward=e['from']=='client';expected.append((us,s,e,forward))
 assert len(expected)==len(frames)-2
 for (t,ip,seg),(us,s,e,forward) in zip(frames[2:],sorted(expected,key=lambda x:x[0])):
  assert t==us and ip[9]==6;assert socket.inet_ntoa(ip[12:16])==d['roles']['client' if forward else s['peer']];assert socket.inet_ntoa(ip[16:20])==d['roles'][s['peer'] if forward else 'client'];sp,dp,seq,ack=struct.unpack_from('!HHII',seg);assert (sp,dp)==((s['clientPort'],s['peerPort']) if forward else (s['peerPort'],s['clientPort']));assert (seq,ack)==(e['seq'],e['ack']);assert seg[13]==sum({'F':1,'S':2,'R':4,'P':8,'A':16}[f] for f in e['flags']);assert seg[(seg[12]>>4)*4:]==e.get('payloadText','').encode()
 return {'pass':True,'sha256':hashlib.sha256(b).hexdigest(),'fileBytes':len(b),'frames':24,'boundedFrames':21,'dnsAnswerFrame':2,'dnsAnswers':rows[1]['dns.a'].split(','),'candidateEstablishedFrames':list(range(3,10)),'candidateAttemptFrames':[20,21],'httpFrames':list(range(10,17)),'incidentalFrames':[17,18,19],'excludedFrames':[22,23,24],'allRawIpAndTransportChecksumsValid':True,'allDesignedTcpFieldsAndPayloadsMatch':True,'tsharkRows':rows}
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--scenario',required=True);a.add_argument('--capture',required=True);a.add_argument('--tshark',default='tshark');x=a.parse_args();print(json.dumps(check(x.capture,x.scenario,x.tshark),indent=2))
