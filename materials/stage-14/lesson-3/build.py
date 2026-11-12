import ssl,struct,socket,hashlib,json,pathlib,subprocess,tempfile
out=pathlib.Path(__file__).parent/'cmuxy281000ddjkfo8qdyv7fr'
def ck(b):
 if len(b)%2:b+=b'\0'
 v=sum(struct.unpack('!%dH'%(len(b)//2),b));v=(v>>16)+(v&65535);v+=(v>>16);return (~v)&65535
packets=[];seq=[1000,9000]; ips=['192.0.2.10','198.51.100.20'];ports=[54000,443]
def emit(i,payload=b'',flags=24):
 j=1-i;s=socket.inet_aton(ips[i]);d=socket.inet_aton(ips[j]);tcp=struct.pack('!HHIIBBHHH',ports[i],ports[j],seq[i],seq[j],80,flags,65535,0,0)+payload
 checksum=ck(s+d+struct.pack('!BBH',0,6,len(tcp))+tcp);tcp=tcp[:16]+struct.pack('!H',checksum)+tcp[18:]
 ip=struct.pack('!BBHHHBBH4s4s',69,0,20+len(tcp),len(packets)+1,0,64,6,0,s,d);ip=ip[:10]+struct.pack('!H',ck(ip))+ip[12:];packets.append(bytes.fromhex('0200000000020200000000010800')+ip+tcp);seq[i]+=len(payload)+(1 if flags&3 else 0)
with tempfile.TemporaryDirectory() as td:
 td=pathlib.Path(td);subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(td/'key.pem'),'-out',str(td/'cert.pem'),'-days','2','-subj','/CN=tls.academy.test'],check=True,capture_output=True)
 server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);server.load_cert_chain(td/'cert.pem',td/'key.pem');server.minimum_version=server.maximum_version=ssl.TLSVersion.TLSv1_2
 client=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);client.check_hostname=False;client.verify_mode=ssl.CERT_NONE;client.minimum_version=client.maximum_version=ssl.TLSVersion.TLSv1_2
 client.keylog_filename=str(out/'controlled-tls-session.keys')
 bios=[(ssl.MemoryBIO(),ssl.MemoryBIO()) for _ in range(2)]; ends=[client.wrap_bio(*bios[0],server_hostname='tls.academy.test'),server.wrap_bio(*bios[1],server_side=True)]
 emit(0,flags=2);emit(1,flags=18);emit(0,flags=16)
 def transfer(i):
  b=bios[i][1].read()
  if b:emit(i,b);bios[1-i][0].write(b);emit(1-i,flags=16)
 done=[False,False]
 for _ in range(30):
  for i in range(2):
   if not done[i]:
    try:ends[i].do_handshake();done[i]=True
    except ssl.SSLWantReadError:pass
   transfer(i)
  if all(done):break
 assert all(done)
 request=b'GET /academy/tls-check HTTP/1.1\r\nHost: tls.academy.test\r\nConnection: close\r\n\r\n';body=b'Academy controlled TLS check OK\n';response=b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
 ends[0].write(request);transfer(0);assert ends[1].read()==request
 ends[1].write(response);transfer(1);assert ends[0].read()==response
 p=out/'transport.pcap'
 with p.open('xb') as f:
  f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
  for n,b in enumerate(packets):f.write(struct.pack('<IIII',1737028800,n*100000,len(b),len(b))+b)
 subprocess.run(['editcap','-F','pcapng',str(p),str(out/'controlled-tls-session.pcapng')],check=True,capture_output=True);p.unlink()
 (out/'generation-receipt.json').write_text(json.dumps({'origin':'Academy actual OpenSSL TLS1.2 encryption using Python ssl.MemoryBIO, serialized as synthetic documentation-network Ethernet/TCP transport; no network traffic collected','client':ips[0]+':54000','server':ips[1]+':443','request':request.decode(),'response':response.decode(),'packets':len(packets),'tlsVersion':ends[0].version(),'cipher':ends[0].cipher(),'captureContainsDecryptionSecretsBlock':False,'keyLog':'Separate disposable session secrets; certificate private key temporary and removed; not a production secret','captureSha256':hashlib.sha256((out/'controlled-tls-session.pcapng').read_bytes()).hexdigest()},indent=2))
