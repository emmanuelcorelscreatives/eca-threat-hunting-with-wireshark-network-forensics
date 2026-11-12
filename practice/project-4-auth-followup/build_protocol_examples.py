from pathlib import Path
import argparse,struct,socket,base64,json,hashlib
p=argparse.ArgumentParser(description='Build non-authenticating offline Kerberos and NTLMSSP teaching bytes');p.add_argument('--out-dir',required=True,type=Path);a=p.parse_args();out=a.out_dir
if out.exists():raise SystemExit('Refusing existing output directory')
out.mkdir(parents=True)
def csum(b):
 if len(b)%2:b+=b'\0'
 s=sum(struct.unpack('!%dH'%(len(b)//2),b));s=(s>>16)+(s&65535);s+=(s>>16);return (~s)&65535
def ip(src,dst,proto,payload):
 aa=socket.inet_aton(src);bb=socket.inet_aton(dst);h=struct.pack('!BBHHHBBH4s4s',69,0,20+len(payload),2,0,64,proto,0,aa,bb);h=h[:10]+struct.pack('!H',csum(h))+h[12:];return bytes.fromhex('0200000000020200000000010800')+h+payload
def udp(src,dst,sp,dp,payload):
 h=struct.pack('!HHHH',sp,dp,8+len(payload),0)+payload;ch=csum(socket.inet_aton(src)+socket.inet_aton(dst)+struct.pack('!BBH',0,17,len(h))+h);return ip(src,dst,17,h[:6]+struct.pack('!H',ch or 65535)+h[8:])
def tcp(src,dst,sp,dp,seq,ack,fl,payload=b''):
 h=struct.pack('!HHIIBBHHH',sp,dp,seq,ack,80,fl,64240,0,0)+payload;ch=csum(socket.inet_aton(src)+socket.inet_aton(dst)+struct.pack('!BBH',0,6,len(h))+h);return ip(src,dst,6,h[:16]+struct.pack('!H',ch)+h[18:])
def tlv(tag,v):return bytes([tag])+ (bytes([len(v)]) if len(v)<128 else bytes([129,len(v)]))+v
def integer(v):return tlv(2,v.to_bytes(max(1,(v.bit_length()+7)//8),'big'))
def ctx(i,v):return tlv(160+i,v)
def seq(v):return tlv(48,v)
def gs(s):return tlv(27,s.encode())
def principal(parts,kind=1):return seq(ctx(0,integer(kind))+ctx(1,seq(b''.join(gs(x) for x in parts))))
realm='EXAMPLE.TEST'
body=seq(ctx(0,tlv(3,b'\0\0\0\0\0'))+ctx(1,principal(['svc-lab']))+ctx(2,gs(realm))+ctx(3,principal(['krbtgt',realm],2))+ctx(5,tlv(24,b'20260101010000Z'))+ctx(7,integer(123))+ctx(8,seq(integer(18))))
request=tlv(106,seq(ctx(1,integer(5))+ctx(2,integer(10))+ctx(4,body)))
def krberror(code):return tlv(126,seq(ctx(0,integer(5))+ctx(1,integer(30))+ctx(4,tlv(24,b'20260101000010Z'))+ctx(5,integer(500000 if code==24 else 700000))+ctx(6,integer(code))+ctx(7,gs(realm))+ctx(8,principal(['svc-lab']))+ctx(9,gs(realm))+ctx(10,principal(['krbtgt',realm],2))+ctx(11,gs('synthetic teaching record'))))
frames=[]
for offset,port,code in [(10.45,41600,24),(10.65,41601,25)]:frames.append((offset,udp('192.0.2.10','192.0.2.40',port,88,request)));frames.append((offset+.05,udp('192.0.2.40','192.0.2.10',88,port,krberror(code))))
def secbuf(n,offset):return struct.pack('<HHI',n,n,offset)
flags=0x00008201
m1=b'NTLMSSP\0'+struct.pack('<II',1,flags)+secbuf(0,32)+secbuf(0,32)
m2=b'NTLMSSP\0'+struct.pack('<I',2)+secbuf(0,48)+struct.pack('<I',flags)+b'\0'*8+b'\0'*8+secbuf(0,48)
domain='EXAMPLE'.encode('utf-16le');user='svc-lab'.encode('utf-16le');work='LAB-CLIENT'.encode('utf-16le');off=64
m3=b'NTLMSSP\0'+struct.pack('<I',3)+secbuf(0,64)+secbuf(0,64)+secbuf(len(domain),off)+secbuf(len(user),off+len(domain))+secbuf(len(work),off+len(domain)+len(user))+secbuf(0,off+len(domain)+len(user)+len(work))+struct.pack('<I',flags)+domain+user+work
enc=lambda b:base64.b64encode(b).decode()
q1=('GET /synthetic HTTP/1.1\r\nHost: app-b.example.test\r\nAuthorization: NTLM '+enc(m1)+'\r\n\r\n').encode();s2=('HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM '+enc(m2)+'\r\nContent-Length: 0\r\n\r\n').encode();q3=('GET /synthetic HTTP/1.1\r\nHost: app-b.example.test\r\nAuthorization: NTLM '+enc(m3)+'\r\n\r\n').encode();s4=b'HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n'
A='192.0.2.10';B='192.0.2.21';sp=42000;seqA=1000;seqB=2000
frames +=[(12,tcp(A,B,sp,80,seqA,0,2)),(12.01,tcp(B,A,80,sp,seqB,seqA+1,18)),(12.02,tcp(A,B,sp,80,seqA+1,seqB+1,16))];seqA+=1;seqB+=1
for tm,isclient,payload in [(12.1,True,q1),(12.2,False,s2),(12.3,True,q3),(12.4,False,s4)]:
 frames.append((tm,tcp(A,B,sp,80,seqA,seqB,24,payload) if isclient else tcp(B,A,80,sp,seqB,seqA,24,payload)))
 if isclient:seqA+=len(payload)
 else:seqB+=len(payload)
frames +=[(12.6,tcp(A,B,sp,80,seqA,seqB,17)),(12.61,tcp(B,A,80,sp,seqB,seqA+1,17)),(12.62,tcp(A,B,sp,80,seqA+1,seqB+1,16))]
b=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
for t,f in frames:b+=struct.pack('<IIII',1767225600+int(t),round((t-int(t))*1e6),len(f),len(f))+f
(out/'protocol-examples.pcap').write_bytes(b);(out/'protocol-examples-spec.json').write_text(json.dumps({'scope':'Offline synthetic protocol-shaped teaching packets; no live authentication; not saved case','authoritativeSource':'build_protocol_examples.py contains complete byte construction; no separate input specification is claimed','packetCount':len(frames),'captureSha256':hashlib.sha256(b).hexdigest(),'kerberos':'AS-REQ with svc-lab cname and EXAMPLE.TEST realm, no PA-DATA; designed KRB-ERROR codes24/25. KDC stime and susec correspond to packet timestamps10.5/10.7; no real KDC response/authentication occurred','ntlmssp':'HTTP-encapsulated Type1/2/3; zero teaching challenge and EMPTY LM/NT response security buffers, not a valid credential response. Type3 names fictional svc-lab,EXAMPLE,LAB-CLIENT; HTTP401 rejects after Type3. Never a successful NTLM authentication','correlation':'Designed matching account/source/event fields enable tentative comparison with EV01,EV02,EV04. EV03 4776 still lacks destination and cannot establish target association; no cryptographic or real-host correlation proved'},indent=2));print(json.dumps({'frames':len(frames),'sha256':hashlib.sha256(b).hexdigest()}))
