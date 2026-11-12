#!/usr/bin/env python3
"""Read-only independent PCAP integrity and scenario join check. Run from kit directory."""
import struct,json,datetime,ipaddress,hashlib
from pathlib import Path

def ck(b):
 b+=b'\0'*(len(b)%2); n=sum(struct.unpack('!%dH'%(len(b)//2),b))
 while n>>16:n=(n&65535)+(n>>16)
 return (~n)&65535

def utc(s):return datetime.datetime.fromisoformat(s.replace('Z','+00:00')).timestamp()

def verify(root=Path('.')):
 context=json.loads((root/'context.json').read_text()); results={}; assets={x['asset_id']:x for x in context['assets']}
 assert len(assets)==len(context['assets'])
 for c in context['captures']:
  raw=(root/c['filename']).read_bytes(); spec=json.loads((root/c['spec']).read_text()); assert raw[:4]==b'\xd4\xc3\xb2\xa1'
  offset=24; frames=[]; streams={}; last=-1
  while offset<len(raw):
   sec,micro,cap,orig=struct.unpack_from('<IIII',raw,offset);offset+=16; frame=raw[offset:offset+cap];offset+=cap
   assert cap==orig==len(frame) and frame[12:14]==b'\x08\x00'
   ip=frame[14:]; hlen=(ip[0]&15)*4; assert len(ip)==struct.unpack_from('!H',ip,2)[0] and ck(ip[:hlen])==0
   proto=ip[9];body=ip[hlen:];assert proto in (6,17)
   assert ck(ip[12:20]+struct.pack('!BBH',0,proto,len(body))+body)==0
   src=str(ipaddress.ip_address(ip[12:16]));dst=str(ipaddress.ip_address(ip[16:20]));sport,dport=struct.unpack_from('!HH',body); t=sec+micro/1e6;assert t>=last;last=t
   e=spec['events'][len(frames)];assert abs(t-utc(e['timestamp']))<1e-6 and (src,dst,sport,dport)==(e['src'],e['dst'],e['sport'],e['dport'])
   for addr in (src,dst):assert any(ipaddress.ip_address(addr) in ipaddress.ip_network(n) for n in ['192.0.2.0/24','198.51.100.0/24','203.0.113.0/24'])
   if proto==6:
    seq,ack=struct.unpack_from('!II',body,4);flags=body[13];expected=sum({'F':1,'S':2,'R':4,'P':8,'A':16,'U':32,'E':64,'C':128}[f] for f in e['flags'])
    assert (seq,ack,flags)==(e['seq'],e['ack'],expected)
    payload=body[(body[12]>>4)*4:]; key=tuple(sorted([(src,sport),(dst,dport)]));state=streams.setdefault(key,{})
    if (src,sport) in state:assert seq==state[(src,sport)]
    state[(src,sport)]=seq+len(payload)+bool(flags&2)+bool(flags&1)
    if flags&16 and (dst,dport) in state:assert ack==state[(dst,dport)]
   else:payload=body[8:];assert struct.unpack_from('!H',body,4)[0]==len(body)
   assert payload==e.get('payloadText','').encode()
   frames.append(dict(frame=len(frames)+1,epoch=t,source=src,destination=dst,protocol='TCP' if proto==6 else 'UDP',packetBytes=len(frame)))
  assert offset==len(raw) and len(frames)==len(spec['events'])
  assert [frames[0]['epoch'],frames[-1]['epoch']]==[utc(x) for x in c['intendedWindowUtc']]
  leads={}
  for lead,peer in [('backup','198.51.100.10'),('monitoring','198.51.100.20'),('unexplained-peer','203.0.113.77')]:
   ff=[f for f in frames if peer in (f['source'],f['destination'])]; leads[lead]={'frames':[f['frame'] for f in ff],'packets':len(ff),'packetBytes':sum(f['packetBytes'] for f in ff)}
  for j in context['jobs']:
   assert j['asset_id'] in assets
   if j['window_start_utc'][:10]==spec['events'][0]['timestamp'][:10]:
    matches=[f for f in frames if {f['source'],f['destination']}=={assets[j['asset_id']]['ip'],j['peer_ip']}];assert matches and all(utc(j['window_start_utc'])<=f['epoch']<=utc(j['window_end_utc']) for f in matches)
  for d in context['deviceRecords']:
   assert d['asset_id'] in assets and utc(d['effective_utc'])<=frames[0]['epoch']
   assert any({f['source'],f['destination']}=={assets[d['asset_id']]['ip'],d['peer_ip']} for f in frames)
  assert {x['lead_id'] for x in context['telemetry']}==set(leads)
  results[c['filename']]={'sha256':hashlib.sha256(raw).hexdigest(),'frames':len(frames),'packetBytes':sum(f['packetBytes'] for f in frames),'firstUtc':spec['events'][0]['timestamp'],'lastUtc':spec['events'][-1]['timestamp'],'leads':leads,'actualFrames':frames}
 return {'status':'PASS','scope':'read-only binary checksums TCP sequence acknowledgment progression times event equality context joins; synthetic metadata is not packet-derived identity','captures':results}
if __name__=='__main__':print(json.dumps(verify(),indent=2))
