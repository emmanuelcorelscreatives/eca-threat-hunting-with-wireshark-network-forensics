"""Offline deterministic synthetic Ethernet builder; Python standard library only."""
import argparse,csv,datetime,ipaddress,pathlib,struct
M=dict(C='02:00:00:00:00:44',S='02:00:00:00:00:02',G='02:00:00:00:00:01',F='02:00:00:00:00:50',P='02:00:00:00:00:60',Q='02:00:00:00:00:61',R='02:00:00:00:10:01',V='02:00:00:00:10:02',B='ff:ff:ff:ff:ff:ff',Z='00:00:00:00:00:00',M='01:00:5e:00:00:fb')
def mac(x): return bytes.fromhex(M.get(x,x).replace(':',''))
def ip(x): return ipaddress.IPv4Address(x).packed
def checksum(b):
 b+=b'\0'*(len(b)%2); s=sum(struct.unpack('!%dH'%(len(b)//2),b)); s=(s&65535)+(s>>16); s=(s&65535)+(s>>16); return (~s)&65535

def dnsname(s):return b''.join(bytes([len(p)])+p.encode() for p in s.split('.'))+b'\0'
def packet(row):
 f=dict(x.split('=',1) for x in row['fields'].split(';')); eth=mac(row['ether_dst'])+mac(row['ether_src'])
 if row['protocol']=='ARP':
  return eth+b'\x08\x06'+struct.pack('!HHBBH',1,0x800,6,4,int(f['op']))+mac(f['sha'])+ip(f['spa'])+mac(f['tha'])+ip(f['tpa'])
 sp,dp=map(int,f['udp'].split('>'))
 if row['protocol']=='DHCP':
  typ=dict(DISCOVER=1,OFFER=2,REQUEST=3,ACK=5)[f['msg']]; reply=typ in (2,5)
  payload=struct.pack('!BBBBIHH',2 if reply else 1,1,6,1 if f['gi']!='0.0.0.0' else 0,int(f['xid'],16),0,0x8000 if row['ip_dst']=='255.255.255.255' else 0)
  payload+=ip(f['ci'])+ip(f['yi'])+ip(f.get('server','0.0.0.0') if reply else '0.0.0.0')+ip(f['gi'])+mac(f['chaddr'])+bytes(10+64+128)+b'\x63\x82\x53\x63'+bytes([53,1,typ])
  for k,code in [('server',54),('requested',50),('lease',51)]:
   if k in f:payload+=bytes([code,4])+(struct.pack('!I',int(f[k])) if k=='lease' else ip(f[k]))
  payload+=b'\xff';payload+=bytes(max(0,300-len(payload)))
 elif row['protocol']=='mDNS':
  name=dnsname(f['name'])
  if f['qr']=='query':payload=struct.pack('!6H',0,0,1,0,0,0)+name+struct.pack('!HH',1,0x8001)
  else:payload=struct.pack('!6H',0,0x8400,0,1,0,0)+name+struct.pack('!HHIH',1,1,60,4)+ip(f['answer'])
 else:payload=bytes(map(int,f['payloadDecimalOctets'].split('|')))
 src,dst=ip(row['ip_src']),ip(row['ip_dst']); udp=struct.pack('!HHHH',sp,dp,len(payload)+8,0)+payload
 cs=checksum(src+dst+struct.pack('!BBH',0,17,len(udp))+udp) or 65535;udp=udp[:6]+struct.pack('!H',cs)+udp[8:]
 hdr=struct.pack('!BBHHHBBH',0x45,0,len(udp)+20,0,0,255 if row['protocol']=='mDNS' else 64,17,0)+src+dst;hdr=hdr[:10]+struct.pack('!H',checksum(hdr))+hdr[12:]
 return eth+b'\x08\x00'+hdr+udp

def main():
 p=argparse.ArgumentParser();p.add_argument('--out-dir',required=True);a=p.parse_args();out=pathlib.Path(a.out_dir);out.mkdir(parents=True,exist_ok=True)
 rows=list(csv.DictReader((pathlib.Path(__file__).parent/'scenario-plan.csv').open()))
 names=['client-facing-synthetic','relay-server-side-synthetic'];targets=[out/(n+'.pcap') for n in names]
 if any(x.exists() for x in targets):raise SystemExit('Refusing overwrite')
 for name,target in zip(names,targets):
  b=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
  for row in rows:
   if row['trace_id']!=name:continue
   ts=datetime.datetime.fromisoformat(row['time_utc'].replace('Z','+00:00')).timestamp();us=round(ts*1000000);data=packet(row);b+=struct.pack('<IIII',us//1000000,us%1000000,len(data),len(data))+data
  with target.open('xb') as f:f.write(b)
if __name__=='__main__':main()
