#!/usr/bin/env python3
"""Read-only independent PCAPNG framing, IP/TCP checksum and TShark verifier."""
import pathlib,struct,hashlib,subprocess,json,csv,io,argparse
p=argparse.ArgumentParser();p.add_argument('capture');a=p.parse_args();f=pathlib.Path(a.capture);b=f.read_bytes();assert b[:4]==b'\x0a\x0d\x0d\x0a';o=0;frames=[]
def csum(d):
 if len(d)%2:d+=b'\0'
 n=sum(struct.unpack('!%dH'%(len(d)//2),d))
 while n>>16:n=(n&65535)+(n>>16)
 return n
while o<len(b):
 typ,n=struct.unpack_from('<II',b,o);assert n>=12 and n%4==0 and o+n<=len(b) and struct.unpack_from('<I',b,o+n-4)[0]==n
 if typ==6:
  interface,hi,lo,cap,orig=struct.unpack_from('<IIIII',b,o+8);assert interface==0 and cap==orig;pkt=b[o+28:o+28+cap];assert len(pkt)==cap and pkt[12:14]==b'\x08\x00';ip=pkt[14:];hlen=(ip[0]&15)*4;assert len(ip)==struct.unpack_from('!H',ip,2)[0] and csum(ip[:hlen])==65535
  if ip[9]==6:
   tcp=ip[hlen:];pseudo=ip[12:20]+struct.pack('!BBH',0,6,len(tcp));assert csum(pseudo+tcp)==65535
  frames.append({'frame':len(frames)+1,'epoch':(hi<<32|lo)/1e6,'bytes':cap})
 o+=n
assert len(frames)==30
fields=['frame.number','frame.time_epoch','ip.src','ip.dst','tcp.srcport','tcp.dstport','tcp.flags','dns.qry.name','dns.a','tls.handshake.type','tls.handshake.extensions_server_name']
cmd=['tshark','-n','-r',str(f),'-T','fields','-E','header=y','-E','separator=,','-E','quote=d']
for field in fields:cmd+=['-e',field]
q=subprocess.run(cmd,capture_output=True,text=True,check=True);rows=list(csv.DictReader(io.StringIO(q.stdout)));assert len(rows)==30
assert [int(r['frame.number']) for r in rows if r['tls.handshake.type']=='1']==[13,14,25,26]
assert [int(r['frame.number']) for r in rows if r['tls.handshake.type']=='2']==[15,16,27,28]
assert [int(r['frame.number']) for r in rows if r['tcp.flags']=='0x0002']==[7,8,19,20]
mal=subprocess.run(['tshark','-n','-r',str(f),'-Y','_ws.malformed','-T','fields','-e','frame.number'],capture_output=True,text=True,check=True);assert not mal.stdout.strip()
conv=subprocess.run(['tshark','-n','-r',str(f),'-q','-z','conv,tcp'],capture_output=True,text=True,check=True)
cap=subprocess.run(['capinfos','-a','-e','-c','-s',str(f)],capture_output=True,text=True,check=True)
print(json.dumps({'state':'PASS','synthetic':True,'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'frameCount':len(frames),'firstEpoch':frames[0]['epoch'],'lastEpoch':frames[-1]['epoch'],'independentRawChecks':'PCAPNG blocks, IPv4 lengths/checksums, every TCP checksum','decodedFieldsCsv':q.stdout,'conversations':conv.stdout,'capinfos':cap.stdout,'commandsActuallyExecuted':[cmd,['tshark','-n','-r',str(f),'-q','-z','conv,tcp'],['capinfos','-a','-e','-c','-s',str(f)]],'limits':'Authored TLS ClientHello and ServerHello only; no completed TLS handshake, certificate or application messages. No real host process ownership or collector coverage.'},indent=2))
