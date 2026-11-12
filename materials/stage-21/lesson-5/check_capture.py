#!/usr/bin/env python3
"""Independent standard-library classic PCAP checker against authored event specs. Offline only."""
import argparse,datetime,json,pathlib,struct,ipaddress,hashlib

def require(v,msg):
 if not v: raise ValueError(msg)
def checksum(b):
 b+=b'\0'*(len(b)%2);s=sum(struct.unpack('!%dH'%(len(b)//2),b))
 while s>>16:s=(s&65535)+(s>>16)
 return s&65535

def check(specpath,capture):
 spec=json.loads(specpath.read_text()); b=capture.read_bytes();require(b[:4]==b'\xd4\xc3\xb2\xa1','Expected little endian classic PCAP');require(struct.unpack_from('<I',b,20)[0]==1,'Expected Ethernet');off=24;rows=[]
 while off<len(b):
  require(off+16<=len(b),'Truncated record');sec,usec,cap,wire=struct.unpack_from('<IIII',b,off);off+=16;require(cap==wire and off+cap<=len(b),'Truncation');f=b[off:off+cap];off+=cap;require(len(f)>=34 and f[12:14]==b'\x08\x00','Ethernet IPv4');ip=f[14:];ihl=(ip[0]&15)*4;require(ihl==20 and len(ip)==struct.unpack_from('!H',ip,2)[0],'IP length');require(checksum(ip[:ihl])==65535,'IP checksum');proto=ip[9];src=str(ipaddress.ip_address(ip[12:16]));dst=str(ipaddress.ip_address(ip[16:20]));t=ip[ihl:];require(proto in [6,17],'Protocol');require(checksum(ip[12:20]+struct.pack('!BBH',0,proto,len(t))+t)==65535,'Transport checksum');sp,dp=struct.unpack_from('!HH',t);e=spec['events'][len(rows)];expected=round(datetime.datetime.fromisoformat(e['timestamp'].replace('Z','+00:00')).timestamp()*1000000);require(sec*1000000+usec==expected,'Time mismatch');require((src,dst,sp,dp)==(e['src'],e['dst'],e['sport'],e['dport']),'Endpoints');require(proto==(6 if e['kind']=='tcp' else 17),'Wrong protocol')
  if proto==6:
   seq,ack=struct.unpack_from('!II',t,4);flags=t[13];want=sum({'F':1,'S':2,'R':4,'P':8,'A':16,'U':32,'E':64,'C':128}[c] for c in e['flags']);require((seq,ack,flags)==(e['seq'],e['ack'],want),'TCP fields');body=t[(t[12]>>4)*4:]
  else:
   require(struct.unpack_from('!H',t,4)[0]==len(t),'UDP length');body=t[8:]
  require(body==e.get('payloadText','').encode(),'Payload mismatch');rows.append(dict(frame=len(rows)+1,timestamp=e['timestamp'],src=src,dst=dst,protocol=proto,sport=sp,dport=dp))
 require(len(rows)==len(spec['events']),'Missing planned events');return dict(capture=capture.name,sha256=hashlib.sha256(b).hexdigest(),bytes=len(b),frames=rows)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--spec',type=pathlib.Path,required=True);p.add_argument('--capture',type=pathlib.Path,required=True);a=p.parse_args();print(json.dumps(check(a.spec,a.capture),indent=2))
