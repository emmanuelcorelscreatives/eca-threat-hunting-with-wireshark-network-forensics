"""Read-only exact identity, PCAP and independent TCP sequence validation."""
import argparse,pathlib,hashlib,struct,json
EXPECTED={'dns.pcap':'0296127000e0664983075f9380dd5e8076441dbe1d3e28b35966596696a445b4','tls.pcap':'a4b30a0d62411f7ba75d85d2671ed4aa52adb4f57d9981a36ba0d92e503f72db'}
def verify(root):
 counts={}
 for name,expected in EXPECTED.items():
  b=(root/name).read_bytes()
  if hashlib.sha256(b).hexdigest()!=expected:raise ValueError('Unapproved capture identity: '+name)
  if b[:4]!=bytes.fromhex('d4c3b2a1'):raise ValueError('PCAP magic')
  off=24;count=0;states={}
  while off<len(b):
   sec,us,n,orig=struct.unpack_from('<IIII',b,off);p=b[off+16:off+16+n];off+=16+n;count+=1
   if len(p)!=n or n!=orig:raise ValueError('Truncated packet')
   if name=='tls.pcap':
    src=p[26:30];dst=p[30:34];sp,dp,seq,ack=struct.unpack_from('!HHII',p,34);flags=p[47];size=len(p)-54;flow=tuple(sorted([(src,sp),(dst,dp)]));s=states.setdefault(flow,{});sender=(src,sp);peer=(dst,dp)
    if sender in s and seq!=s[sender]:raise ValueError('TCP sequence')
    if flags&16 and ack!=s.get(peer):raise ValueError('TCP acknowledgment')
    if flags==2 and ack!=0:raise ValueError('Initial SYN acknowledgment')
    s[sender]=seq+size+bool(flags&2)+bool(flags&1)
  if off!=len(b) or count!=(12 if name=='dns.pcap' else 132):raise ValueError('Packet count/record boundary')
  if name=='tls.pcap' and len(states)!=6:raise ValueError('Session count')
  counts[name]=count
 return counts
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--directory',type=pathlib.Path,default=pathlib.Path(__file__).parent);a=p.parse_args();print(json.dumps({'verified':verify(a.directory)}))
