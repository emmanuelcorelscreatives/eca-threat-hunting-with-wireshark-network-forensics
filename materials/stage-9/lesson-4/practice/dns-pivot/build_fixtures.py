#!/usr/bin/env python3
"""Generate deterministic, documentation-address-only synthetic Ethernet PCAPs offline."""
import argparse,datetime,hashlib,ipaddress,json,struct
from pathlib import Path
from limited_builder import checksum,dns_name,uint

def address(value):
 ip=ipaddress.ip_address(value)
 nets=['192.0.2.0/24','198.51.100.0/24','203.0.113.0/24'] if ip.version==4 else ['2001:db8::/32']
 if not any(ip in ipaddress.ip_network(n) for n in nets): raise ValueError('Documentation addresses required')
 return ip

def packet(e,ident):
 src,dst=address(e['src']),address(e['dst']);a,b=src.packed,dst.packed
 if src.version!=dst.version:raise ValueError('IP versions differ')
 if e['kind'].startswith('dns-'):
  question=dns_name(e['name'])+struct.pack('!HH',1,1); records=e['records'];rbytes=b''
  for r in records:
   typ={'A':1,'AAAA':28,'CNAME':5}[r['type']]
   value=dns_name(r['value']) if typ==5 else address(r['value']).packed
   if typ==1 and len(value)!=4 or typ==28 and len(value)!=16:raise ValueError('RR address type mismatch')
   rbytes+=dns_name(r['owner'])+struct.pack('!HHIH',typ,1,uint(r['ttl'],0xffffffff),len(value))+value
  reply=e['kind']=='dns-answer'
  body=struct.pack('!HHHHHH',uint(e['transactionId'],65535),0x8180 if reply else 0x100,1,len(records),0,0)+question+rbytes
  proto=17;head=struct.pack('!HHHH',e['sport'],e['dport'],8+len(body),0)
 elif e['kind']=='tcp':
  proto=6;body=b'';flags=sum({'S':2,'A':16}[f] for f in e['flags'])
  head=struct.pack('!HHIIBBHHH',uint(e['sport'],65535),uint(e['dport'],65535),e['seq'],e['ack'],80,flags,65535,0,0)
 else:raise ValueError('Unknown event')
 length=len(head)+len(body)
 pseudo=a+b+(struct.pack('!BBH',0,proto,length) if src.version==4 else struct.pack('!I3xB',length,proto))
 value=checksum(pseudo+head+body) or 65535
 offset=6 if proto==17 else 16;transport=head[:offset]+struct.pack('!H',value)+head[offset+2:]+body
 if src.version==4:
  iph=struct.pack('!BBHHHBBH4s4s',69,0,20+length,ident,0,64,proto,0,a,b);iph=iph[:10]+struct.pack('!H',checksum(iph))+iph[12:];eth=b'\x08\x00'
 else:iph=struct.pack('!IHBB16s16s',6<<28,length,proto,64,a,b);eth=b'\x86\xdd'
 return bytes.fromhex('020000000002020000000001')+eth+iph+transport

def generate(events):
 data=bytearray(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1));prev=-1
 for n,e in enumerate(events,1):
  t=datetime.datetime.fromisoformat(e['timestamp'].replace('Z','+00:00'))
  if t.utcoffset()!=datetime.timedelta(0):raise ValueError('UTC required')
  d=t-datetime.datetime(1970,1,1,tzinfo=datetime.timezone.utc);micro=(d.days*86400+d.seconds)*1000000+d.microseconds
  if micro<prev:raise ValueError('Timestamp order');
  prev=micro;pkt=packet(e,n);sec,us=divmod(micro,1000000);data+=struct.pack('<IIII',sec,us,len(pkt),len(pkt))+pkt
 return bytes(data)
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--plan',type=Path,required=True);ap.add_argument('--output-dir',type=Path);args=ap.parse_args()
 plan=json.loads(args.plan.read_text());out=args.output_dir or args.plan.parent
 if plan.get('version')!=2 or plan.get('synthetic') is not True:raise ValueError('Explicit synthetic v2 plan required')
 if set(plan['captures'])!={'client-facing.pcap','upstream-only.pcap','no-dns.pcap'}:raise ValueError('Exact three captures required')
 out.mkdir(parents=True,exist_ok=True)
 # Refuse any overwrite before writing even the first file.
 for name in plan['captures']:
  if (out/name).exists():raise FileExistsError(out/name)
 for name,spec in plan['captures'].items():
  data=generate(spec['events']);(out/name).write_bytes(data);print(json.dumps(dict(file=name,bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),frames=len(spec['events']),synthetic=True)))
if __name__=='__main__':main()
