#!/usr/bin/env python3
"""Independent raw-PCAP parser/checks plus actual TShark dissection; no generator import."""
import argparse,csv,datetime,hashlib,ipaddress,json,struct,subprocess
from pathlib import Path

def valid_sum(b):
 if len(b)%2:b+=b'\0'
 s=sum(int.from_bytes(b[i:i+2],'big') for i in range(0,len(b),2))
 while s>65535:s=(s&65535)+(s>>16)
 return s==65535

def dnsname(b,o):
 parts=[]
 while True:
  assert o<len(b);n=b[o];o+=1
  if n==0:return '.'.join(parts),o
  assert n<=63 and o+n<=len(b);parts.append(b[o:o+n].decode('ascii'));o+=n

def check(path,rows,base,tshark):
 b=path.read_bytes();assert len(b)>24 and struct.unpack('<IHHIIII',b[:24])==(0xa1b2c3d4,2,4,0,0,65535,1)
 expected=[]
 for r in rows:
  expected.append((int(r['query_ms']),0,r['row'],r))
  if r['reply_ms']:expected.append((int(r['reply_ms']),1,r['row'],r))
 expected.sort(key=lambda x:x[:3]);o=24;records=[]
 for i,(ms,response,_,r) in enumerate(expected,1):
  sec,usec,cap,wire=struct.unpack('<IIII',b[o:o+16]);o+=16;p=b[o:o+cap];o+=cap
  assert cap==wire==len(p) and (sec,usec)==(base+ms//1000,ms%1000*1000)
  assert p[12:14]==b'\x08\x00';ip=p[14:34];v,tos,total,ident,frag,ttl,proto,c,src,dst=struct.unpack('!BBHHHBBH4s4s',ip)
  assert (v,tos,total,ident,frag,ttl,proto)==(69,0,len(p)-14,i,0,64,17) and valid_sum(ip)
  rs,rd=r['src'],r['dst'];sp,dp=int(r['sport']),53
  if response:rs,rd=rd,rs;sp,dp=dp,sp
  assert str(ipaddress.IPv4Address(src))==rs and str(ipaddress.IPv4Address(dst))==rd
  assert p[:6]==b'\x02\x00'+dst and p[6:12]==b'\x02\x00'+src
  udp=p[34:];sport,dport,ul,uc=struct.unpack('!HHHH',udp[:8]);assert (sport,dport,ul)==(sp,dp,len(udp)) and uc and valid_sum(src+dst+bytes([0,17])+struct.pack('!H',ul)+udp)
  d=udp[8:];id_,flags,qd,an,ns,ar=struct.unpack('!HHHHHH',d[:12]);assert id_==int(r['id']) and qd==1 and ar==0
  nm,k=dnsname(d,12);qt,qc=struct.unpack('!HH',d[k:k+4]);k+=4;assert nm==r['name'] and qt=={'A':1,'AAAA':28}[r['qtype']] and qc==1
  if not response:assert flags==256 and an==ns==0
  else:
   assert flags=={'NOERROR':33152,'NXDOMAIN':33155}[r['rcode']]
   assert (an,ns)==((1,0) if r['answer_a'] else (0,1))
   rn,k=dnsname(d,k);rt,rc,rttl,rl=struct.unpack('!HHIH',d[k:k+10]);k+=10;end=k+rl;assert rc==1
   if r['answer_a']:assert (rn,rt,rttl,rl)==(r['name'],1,60,4) and str(ipaddress.IPv4Address(d[k:end]))==r['answer_a'];k=end
   else:
    assert (rn,rt,rttl)==(r['soa_zone'],6,int(r['soa_ttl_s']));m,k=dnsname(d,k);n,k=dnsname(d,k);nums=struct.unpack('!IIIII',d[k:k+20]);k+=20;assert m=='ns.'+rn and n=='hostmaster.'+rn and nums==(1,3600,600,86400,int(r['soa_minimum_s'])) and k==end
  assert k==len(d)
  records.append({'frame':i,'row':r['row'],'response':bool(response),'relativeMs':ms,'rcode':r['rcode'] if response else None})
 assert o==len(b)
 fields=['frame.number','frame.time_epoch','ip.src','ip.dst','udp.srcport','udp.dstport','dns.id','dns.flags.response','dns.flags.rcode','dns.qry.name','dns.qry.type','dns.count.answers','dns.count.auth_rr','dns.response_to','dns.response_in','dns.retransmit_request','dns.retransmission','ip.checksum.status','udp.checksum.status']
 args=[tshark,'-n','-r',str(path),'-o','ip.check_checksum:TRUE','-o','udp.check_checksum:TRUE','-T','fields','-E','header=y','-E','separator=,','-E','quote=d']+sum((['-e',x] for x in fields),[])
 run=subprocess.run(args,capture_output=True,text=True,check=True);path.with_suffix('.decoded.csv').write_text(run.stdout);path.with_suffix('.decode.stderr.txt').write_text(run.stderr)
 parsed=list(csv.DictReader(run.stdout.splitlines()));assert len(parsed)==len(records)
 for row,record in zip(parsed,records):
  assert row['frame.number']==str(record['frame']) and row['ip.checksum.status']=='1' and row['udp.checksum.status']=='1'
  assert row['dns.flags.response'] in (["True","1"] if record['response'] else ["False","0"])
 bad=subprocess.run([tshark,'-n','-r',str(path),'-Y','_ws.malformed','-T','fields','-e','frame.number'],capture_output=True,text=True,check=True);assert not bad.stdout.strip()
 return {'file':path.name,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'frames':len(records),'rawChecks':'headers, timestamps, tuples, DNS questions/flags/answers/SOA, all lengths, IPv4/UDP checksums and exact EOF','tsharkArgv':args,'tsharkExitCode':run.returncode,'malformedFrames':[],'records':records}

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--spec',type=Path,required=True);ap.add_argument('--client',type=Path,required=True);ap.add_argument('--upstream',type=Path,required=True);ap.add_argument('--tshark',default='tshark');a=ap.parse_args();s=json.loads(a.spec.read_text());rows=list(csv.DictReader((a.spec.parent/s['transactions']).open()));notes=json.loads((a.spec.parent/s['collectionNotes']).read_text());base=int(datetime.datetime.fromisoformat(notes['baseUtc'].replace('Z','+00:00')).timestamp());result={'state':'PASS','synthetic':True,'scope':'actual offline packet validation, not GUI or historical incident evidence','files':[check(p,[r for r in rows if r['view']==v],base,a.tshark) for v,p in [('client-facing',a.client),('upstream',a.upstream)]]};print(json.dumps(result,indent=2))
if __name__=='__main__':main()
