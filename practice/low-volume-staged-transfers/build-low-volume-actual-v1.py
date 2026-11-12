from pathlib import Path
import subprocess,ssl,socket,threading,time,json,hashlib,os,shutil
w=Path('/var/lib/trejj-studio/maintenance/wireshark-pocket-production-20261111');r=w/'low-volume-staged-kit-v1';private=w/'low-volume-staged-private-v1';private.mkdir();h=lambda b:hashlib.sha256(b).hexdigest();events=[]
def log(event,**kw):events.append(dict(time_ns=time.time_ns(),event=event,**kw))
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(private/'key.pem'),'-out',str(r/'lab-certificate.pem'),'-days','1','-subj','/CN=localhost'],check=True,capture_output=True)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(r/'lab-certificate.pem',private/'key.pem');context.minimum_version=ssl.TLSVersion.TLSv1_3
sock=socket.socket();sock.bind(('127.0.0.1',0));sock.listen();port=sock.getsockname()[1]
cap=subprocess.Popen(['tcpdump','-i','lo','-U','-s','0','-w',str(r/'actual-tls-staging.pcap'),'tcp','port',str(port)],stdout=(r/'actual-tcpdump.stdout').open('w'),stderr=(r/'actual-tcpdump.stderr').open('w'));time.sleep(1)
source=private/'source.txt';source.write_bytes(b'ACADEMY LAB ONLY: harmless staged sample\n'*4);staged=private/'staged.bin';shutil.copyfile(source,staged);log('file_copied',sourceName=source.name,stagedName=staged.name,bytes=staged.stat().st_size,sha256=h(staged.read_bytes()))
received=[]
def server():
 for i in range(3):
  raw,addr=sock.accept()
  with context.wrap_socket(raw,server_side=True)as conn:
   payload=b''
   while True:
    b=conn.recv(4096)
    if not b:break
    payload+=b
   received.append(payload);log('server_received',attempt=i+1,bytes=len(payload),sha256=h(payload),peer=str(addr),tls=conn.version())
t=threading.Thread(target=server);t.start();client=ssl.create_default_context();client.check_hostname=False;client.verify_mode=ssl.CERT_NONE
for i in range(3):
 data=staged.read_bytes()[i*52:(i+1)*52];log('client_read_staged_slice',attempt=i+1,start=i*52,end=(i+1)*52,bytes=len(data),sha256=h(data))
 with socket.create_connection(('127.0.0.1',port))as raw:
  with client.wrap_socket(raw,server_hostname='localhost')as conn:conn.sendall(data);log('client_sent',attempt=i+1,bytes=len(data),tls=conn.version());conn.shutdown(socket.SHUT_WR)
 time.sleep([1,3,1][i])
t.join(10);sock.close();time.sleep(1);cap.send_signal(2);cap.wait(timeout=10)
(r/'actual-host-file-events.json').write_text(json.dumps({'scope':'Observed author controlled loopback laboratory; actual host file copy/read and server receive logs, not historical endpoint evidence. Peer IP is same host; destination authorization in original case unknown.','platform':Path('/etc/os-release').read_text(),'events':events,'sourceBytes':source.stat().st_size,'sourceSha256':h(source.read_bytes()),'stagedSha256':h(staged.read_bytes()),'receivedSha256':h(b''.join(received)),'sentSliceBytes':156,'unsentBytes':source.stat().st_size-156,'port':port,'tlsKeysDelivered':False},indent=2))
tshark=w/'native-wireshark-4.4.0-source-v1/build/run/tshark'
for name,args in [('actual-tls-fields',['-T','fields','-E','header=y','-E','separator=,','-e','frame.number','-e','frame.time_epoch','-e','ip.src','-e','tcp.srcport','-e','ip.dst','-e','tcp.dstport','-e','tcp.stream','-e','tcp.len','-e','tls.record.content_type','-e','tls.record.length','-e','_ws.col.Protocol']),('actual-tls-protocols',['-q','-z','io,phs']),('reverse-check',['-Y','ip.src == 198.51.100.77 && ip.dst == 192.0.2.25','-T','fields','-e','frame.number'])]:
 capture=r/('practice.pcap'if name=='reverse-check'else'actual-tls-staging.pcap');argv=[str(tshark),'-n','-r',str(capture)]+args;q=subprocess.run(argv,capture_output=True,text=True);(r/(name+'.stdout.txt')).write_text(q.stdout);(r/(name+'.stderr.txt')).write_text(q.stderr);assert q.returncode==0
(r/'actual-collection-receipt.json').write_text(json.dumps({'captureSha256':h((r/'actual-tls-staging.pcap').read_bytes()),'captureBytes':(r/'actual-tls-staging.pcap').stat().st_size,'hostEventsSha256':h((r/'actual-host-file-events.json').read_bytes()),'realCollection':True,'loopbackOnly':True,'privateKeysOmitted':True,'collectionCode':str(Path(__file__))},indent=2))
