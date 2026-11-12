#!/usr/bin/env python3
"""Read-only validation against fixed reviewed capture hashes and TShark semantics."""
import argparse,csv,hashlib,io,json,shutil,subprocess
from pathlib import Path
EXPECTED={'client-facing.pcap':('3f43256ed7e1feeb55a0b1f81fabb169d5461e6dab08b172976af90f411fe37b',24),'upstream-only.pcap':('2dba086df4abc4dab718a2df0c9678a215863747ecfcdfad5914dd7049946986',5),'no-dns.pcap':('29394bb658d559de830bd015042553bcfbdc7b9f1ccc7a6bad4f8b037e3194ca',3)}
FIELDS=['frame.number','frame.time_epoch','ip.src','ip.dst','ipv6.src','ipv6.dst','dns.flags.response','dns.id','dns.qry.name','dns.resp.name','dns.resp.type','dns.a','dns.aaaa','dns.cname','dns.resp.ttl','tcp.flags','tcp.srcport','tcp.dstport']
def check(ok,message):
 if not ok:raise ValueError(message)
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--plan',type=Path,required=True);ap.add_argument('--capture-dir',type=Path);ap.add_argument('--tshark',default='tshark');args=ap.parse_args();root=args.capture_dir or args.plan.parent
 check(hashlib.sha256(args.plan.read_bytes()).hexdigest()=='6c3edfa93ec08eb7e4975841e8109463254086e8c40d44d21cd482bab96a03fc','Complete reviewed plan hash mismatch');plan=json.loads(args.plan.read_text());check(plan.get('version')==2,'Plan version');check(plan.get('synthetic') is True and set(plan['captures'])==set(EXPECTED),'Plan scope')
 def run(path,extra):
  r=subprocess.run([args.tshark,'-r',str(path),*extra],text=True,capture_output=True);check(r.returncode==0,r.stderr);return r.stdout
 allrows={}
 for name,(digest,count) in EXPECTED.items():
  path=root/name;check(hashlib.sha256(path.read_bytes()).hexdigest()==digest,'Capture hash mismatch: '+name)
  cmd=['-T','fields','-E','header=y','-E','separator=/t']
  for f in FIELDS:cmd+=['-e',f]
  rows=list(csv.DictReader(io.StringIO(run(path,cmd)),delimiter='\t'));check(len(rows)==count,'Frame count');allrows[name]=rows
  check(not run(path,['-Y','_ws.malformed || ip.checksum.status == 0 || tcp.checksum.status == 0 || udp.checksum.status == 0','-o','ip.check_checksum:TRUE','-o','tcp.check_checksum:TRUE','-o','udp.check_checksum:TRUE','-T','fields','-e','frame.number']).strip(),'Malformed or bad checksum')
  check(len(plan['captures'][name]['events'])==count,'Plan frame count')
  print(json.dumps(dict(file=name,sha256=digest,frames=count,malformed=0,badChecksums=0)))
 r=allrows['client-facing.pcap'];answer=r[4]
 check(answer['dns.cname']=='edge.academy.test' and answer['dns.a']=='198.51.100.41,198.51.100.42' and answer['dns.aaaa']=='2001:db8::41','Alias/address records')
 check(answer['dns.resp.name']=='portal.academy.test,edge.academy.test,edge.academy.test,edge.academy.test','RR owners');check(answer['dns.resp.type']=='5,1,1,28','RR types');check(answer['dns.resp.ttl']=='30,60,90,60','RR TTLs');check(r[10]['ipv6.dst']=='2001:db8::41','IPv6 session')
 for q,a in [(4,5),(6,7),(17,18)]:
  x,y=r[q-1],r[a-1];check(x['dns.id']==y['dns.id'] and x['dns.qry.name']==y['dns.qry.name'] and x['ip.src']==y['ip.dst'] and x['ip.dst']==y['ip.src'],'DNS pairing')
 check(all(x['ip.dst']!='198.51.100.43' for x in r),'Unused .43 address')
 check(float(r[21]['frame.time_epoch'])-float(r[4]['frame.time_epoch'])>60,'Late contact after TTL')
 check(all(not x['dns.id'] for x in allrows['no-dns.pcap']),'No-DNS scope')
 check(all(x['ip.src']!='192.0.2.30' for x in allrows['upstream-only.pcap'] if x['dns.id']),'Upstream scope')
 print(json.dumps(dict(verdict='PASS',semantics='Complete reviewed plan hash/version plus fixed capture hashes, selected DNS owners/types/alias/addresses/TTLs, pairing, IPv6 and viewpoint checked',tshark=subprocess.check_output([args.tshark,'--version'],text=True).splitlines()[0])))
if __name__=='__main__':main()
