#!/usr/bin/env python3
"""Fail-closed independent local checks, no network collection."""
import argparse,pathlib,json,struct,hashlib,subprocess,csv,datetime

def check(b):
 if len(b)%2:b+=b'\0'
 s=sum(struct.unpack('!%dH'%(len(b)//2),b));s=(s&65535)+(s>>16);s=(s&65535)+(s>>16);return s==65535

def run(capture,spec,manifest,inventory,config):
 b=pathlib.Path(capture).read_bytes();s=json.loads(pathlib.Path(spec).read_text());m=json.loads(pathlib.Path(manifest).read_text())
 assert hashlib.sha256(b).hexdigest()==m['captureSha256'],'capture hash';assert b[:4]==bytes.fromhex('d4c3b2a1'),'PCAP format'
 off=24;count=0
 while off<len(b):
  sec,usec,n,orig=struct.unpack_from('<IIII',b,off);off+=16;packet=b[off:off+n];off+=n;assert len(packet)==n==orig and n>=54,'record lengths';ip=packet[14:34];tcp=packet[34:];assert check(ip),'IP checksum';assert check(ip[12:20]+struct.pack('!BBH',0,6,len(tcp))+tcp),'TCP checksum';assert struct.unpack('!H',ip[2:4])[0]==n-14,'IP length';count+=1
 assert off==len(b) and count==m['frameCount'],'frame total'
 inv=list(csv.DictReader(open(inventory)));cfg=list(csv.DictReader(open(config)));assert len(inv)==1 and inv[0]['asset_ip']==s['asset'],'inventory'
 assert {r['id'] for r in cfg}=={'UPDATE','MONITOR'},'config rows';assert cfg[0]['peer']=='198.51.100.20' and cfg[1]['peer']=='203.0.113.30','configured peers'
 def tsh(*args):
  p=subprocess.run(['tshark','-n','-o','ip.check_checksum:TRUE','-o','tcp.check_checksum:TRUE','-r',capture,*args],text=True,capture_output=True,check=True);return p.stdout
 bad=tsh('-Y','_ws.malformed || ip.checksum.status == 0 || tcp.checksum.status == 0','-T','fields','-e','frame.number');assert not bad.strip(),'malformed/bad checksum'
 fields=['frame.number','frame.time_epoch','frame.time_relative','ip.src','ip.dst','tcp.srcport','tcp.dstport','tcp.stream','tcp.flags','tcp.seq_raw','tcp.ack_raw','tcp.len']
 raw=tsh('-T','fields','-E','header=y','-E','separator=,',*[a for f in fields for a in ['-e',f]])
 rows=list(csv.DictReader(raw.splitlines()));streams=sorted({int(r['tcp.stream']) for r in rows});assert len(streams)==len(s['connections'])==5,'streams'
 assert len(rows)==count and {r['ip.src'] for r in rows}=={s['asset'],*[c['peer'] for c in s['connections']]},'directions'
 for c in s['connections']:
  cr=[r for r in rows if (r['tcp.srcport']==str(c['client_port']) or r['tcp.dstport']==str(c['client_port']))];assert {r['ip.src'] for r in cr}=={s['asset'],c['peer']},'bidirection';syn=[r for r in cr if r['tcp.flags']=='0x0002'];assert len(syn)==1 and abs(float(syn[0]['frame.time_relative'])-c['start'])<1e-5,'start';assert abs(float(cr[-1]['frame.time_relative'])-(c['start']+c['duration']+.02))<1e-5,'duration';assert len([r for r in cr if int(r['tcp.len'])>0])==2*len(c['exchange_offsets']),'exchanges'
 for c in s['connections']:
  cr=[r for r in rows if (r['tcp.srcport']==str(c['client_port']) or r['tcp.dstport']==str(c['client_port']))]
  client_next=c['client_isn'];server_next=c['server_isn']
  for r in cr:
   client=r['ip.src']==s['asset'];flags=int(r['tcp.flags'],16);seq=int(r['tcp.seq_raw']);ack=int(r['tcp.ack_raw']);length=int(r['tcp.len']);expected=client_next if client else server_next;opposite=server_next if client else client_next
   probe=not(flags&3) and length==0 and seq==expected-1
   assert seq==expected or probe,'sequence context'
   if flags&16:assert ack==opposite,'acknowledgment context'
   advance=length+bool(flags&2)+bool(flags&1)
   if client:client_next+=advance
   else:server_next+=advance
 probes=tsh('-Y','tcp.analysis.keep_alive','-T','fields','-e','frame.number').split();acks=tsh('-Y','tcp.analysis.keep_alive_ack','-T','fields','-e','frame.number').split();assert len(probes)==len(acks)==4,'actual keepalive classifications'
 return {'status':'pass','captureSha256':hashlib.sha256(b).hexdigest(),'frameCount':count,'streamCount':5,'keepAliveFrames':[int(x) for x in probes],'keepAliveAckFrames':[int(x) for x in acks],'firstEpoch':rows[0]['frame.time_epoch'],'lastEpoch':rows[-1]['frame.time_epoch'],'checks':['exact capture hash','all record lengths','all IPv4/TCP checksums','no malformed dissection','five coherent directional conversations','one SYN per connection','raw sequence/ack context through handshake exchanges probes and close','specified starts/durations/payload exchanges','inventory/config peers','four actual TShark probes and four replies'],'tsharkVersion':subprocess.check_output(['tshark','--version'],text=True,stderr=subprocess.DEVNULL).splitlines()[0]},raw
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--capture',default='supplemental_ordinary_traffic.pcap');p.add_argument('--spec',default='fixture_spec.json');p.add_argument('--manifest',default='fixture_manifest.json');p.add_argument('--inventory',default='asset_inventory.csv');p.add_argument('--config',default='approved_configuration.csv');a=p.parse_args();result,raw=run(a.capture,a.spec,a.manifest,a.inventory,a.config);print(json.dumps(result,indent=2))
