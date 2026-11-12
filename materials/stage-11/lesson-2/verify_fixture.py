"""Independent raw reader; does not import the generator or use expected PCAP bytes."""
import argparse,csv,datetime,hashlib,ipaddress,json,struct

def check_sum(b):
 if len(b)%2:b+=b'\0'
 n=sum(int.from_bytes(b[i:i+2],'big') for i in range(0,len(b),2))
 while n>65535:n=(n&65535)+(n>>16)
 assert n==65535,'Checksum mismatch'

def verify(plan,metadata,data):
 assert len(data)>=24 and data[:4]==b'\xd4\xc3\xb2\xa1'
 assert struct.unpack('<HHIIII',data[4:24])==(2,4,0,0,65535,1)
 base=datetime.datetime.fromisoformat(metadata['baseUTC'].replace('Z','+00:00')).timestamp();off=24;seen={};frames=[]
 for i,r in enumerate(plan,1):
  assert off+16<=len(data),'Missing packet';sec,us,cap,wire=struct.unpack('<IIII',data[off:off+16]);off+=16;p=data[off:off+cap];off+=cap
  assert len(p)==cap==wire and sec*1000000+us==round(base*1000000)+int(r['offset_ms'])*1000
  src=ipaddress.ip_address(r['src_ip']).packed;dst=ipaddress.ip_address(r['dst_ip']).packed
  assert p[:14]==b'\x02\x00'+dst+b'\x02\x00'+src+b'\x08\x00';ip=p[14:];assert ip[0]==69 and len(ip)==int.from_bytes(ip[2:4],'big') and ip[12:16]==src and ip[16:20]==dst
  assert int.from_bytes(ip[4:6],'big')==i and ip[6:9]==b'\0\0\x40';check_sum(ip[:20]);body=ip[20:]
  if r['protocol']=='TCP':
   assert ip[9]==6 and len(body)==20
   sp,dp,seq,ack,hl,flags,win,cs,urg=struct.unpack('!HHIIBBHHH',body)
   assert (sp,dp,seq,ack,hl,flags,win,urg)==(int(r['src_port']),int(r['dst_port']),int(r['seq']),int(r['ack']),80,sum({'S':2,'R':4,'A':16}[c] for c in r['tcp_flags']),65535,0)
   check_sum(src+dst+b'\0\x06'+len(body).to_bytes(2,'big')+body)
  else:
   assert ip[9]==1 and len(body)==36 and body[0]==int(r['icmp_type']) and body[1]==int(r['icmp_code']) and body[4:8]==b'\0'*4
   check_sum(body);assert body[8:]==seen[r['quoted_step_id']][:28],'Incorrect quoted packet'
  seen[r['step_id']]=ip;frames.append({'frame':i,'step':r['step_id'],'length':cap,'protocol':r['protocol'],'checksums':'valid'})
 assert off==len(data),'Extra packet or trailing bytes'
 return {'verified':True,'frames':frames,'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'scope':'Synthetic packet bytes; no observed network coverage or intent'}
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--plan',required=True);a.add_argument('--metadata',required=True);a.add_argument('--pcap',required=True);a=a.parse_args()
 print(json.dumps(verify(list(csv.DictReader(open(a.plan))),json.load(open(a.metadata)),open(a.pcap,'rb').read()),indent=2))
