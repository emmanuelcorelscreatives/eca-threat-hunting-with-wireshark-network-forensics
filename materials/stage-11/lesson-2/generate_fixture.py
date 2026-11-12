"""Offline synthetic Ethernet/IPv4/TCP and ICMP fixture. No network I/O."""
import argparse,csv,datetime,hashlib,ipaddress,json,pathlib,struct

def checksum(b):
 if len(b)%2:b+=b'\0'
 s=sum(struct.unpack('!%dH'%(len(b)//2),b))
 while s>>16:s=(s&65535)+(s>>16)
 return (~s)&65535

def ipv4(src,dst,proto,payload,ident):
 h=struct.pack('!BBHHHBBH4s4s',69,0,20+len(payload),ident,0,64,proto,0,src,dst)
 return h[:10]+struct.pack('!H',checksum(h))+h[12:]+payload

def build(plan,metadata):
 base=datetime.datetime.fromisoformat(metadata['baseUTC'].replace('Z','+00:00')).timestamp();packets={};out=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
 for i,r in enumerate(plan,1):
  src=ipaddress.ip_address(r['src_ip']).packed;dst=ipaddress.ip_address(r['dst_ip']).packed
  if r['protocol']=='TCP':
   flags=sum({'S':2,'A':16,'R':4}[c] for c in r['tcp_flags']);p=struct.pack('!HHIIBBHHH',int(r['src_port']),int(r['dst_port']),int(r['seq']),int(r['ack']),80,flags,65535,0,0)
   pseudo=src+dst+struct.pack('!BBH',0,6,len(p));p=p[:16]+struct.pack('!H',checksum(pseudo+p))+p[18:];ip=ipv4(src,dst,6,p,i)
  elif r['protocol']=='ICMP':
   q=packets[r['quoted_step_id']][:28];p=struct.pack('!BBHI',int(r['icmp_type']),int(r['icmp_code']),0,0)+q;p=p[:2]+struct.pack('!H',checksum(p))+p[4:];ip=ipv4(src,dst,1,p,i)
  else:raise ValueError('Unsupported protocol')
  packets[r['step_id']]=ip;eth=b'\x02\x00'+dst+b'\x02\x00'+src+b'\x08\x00'+ip
  us=round(base*1000000)+int(r['offset_ms'])*1000;out+=struct.pack('<IIII',us//1000000,us%1000000,len(eth),len(eth))+eth
 return out
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--plan',required=True);a.add_argument('--metadata',required=True);a.add_argument('--output',required=True);a=a.parse_args()
 data=build(list(csv.DictReader(open(a.plan))),json.load(open(a.metadata)))
 with open(a.output,'xb') as f:f.write(data)
 print(json.dumps({'synthetic':True,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}))
