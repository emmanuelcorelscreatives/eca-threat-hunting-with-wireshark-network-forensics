#!/usr/bin/env python3
"""Create new isolated loopback TLS12+TLS13 practice. Never overwrite files."""
from pathlib import Path
import subprocess as s,tempfile,time,socket,sys,json,os,re
out=Path(sys.argv[1]);out.mkdir(exist_ok=False,parents=True)
def run(args,**kw):return s.run(args,check=True,capture_output=True,**kw)
ports=[]
for i in range(2):
 with socket.socket() as sk:sk.bind(('127.0.0.1',0));ports.append(sk.getsockname()[1])
with tempfile.TemporaryDirectory(prefix='academy-tls-') as tmp:
 t=Path(tmp)
 run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(t/'key.pem'),'-out',str(out/'certificate.pem'),'-days','2','-subj','/CN=shop.academy.test','-addext','subjectAltName=DNS:shop.academy.test,DNS:cdn.academy.test'])
 cap=s.Popen(['dumpcap','-q','-i','lo','-f',f'tcp port {ports[0]} or tcp port {ports[1]}','-w','-'],stdout=(out/'tls-metadata-supplement.pcapng').open('wb'),stderr=(out/'capture.stderr.txt').open('w'))
 time.sleep(1)
 servers=[];logs=[]
 try:
  for version,port in zip(['tls1_2','tls1_3'],ports):
   srv=s.Popen(['openssl','s_server','-accept',f'127.0.0.1:{port}','-cert',str(out/'certificate.pem'),'-key',str(t/'key.pem'),'-'+version,'-www','-naccept','1'],stdout=(out/(version+'-server.txt')).open('w'),stderr=s.STDOUT);servers.append(srv);time.sleep(.4)
   r=run(['openssl','s_client','-connect',f'127.0.0.1:{port}','-servername','shop.academy.test','-'+version,'-CAfile',str(out/'certificate.pem')],input=b'GET / HTTP/1.0\r\nHost: shop.academy.test\r\n\r\n',timeout=8)
   (out/(version+'-client.txt')).write_text(re.sub(r'(?m)^(\s*(?:Master-Key|Resumption PSK):).*$', r'\1 [REMOVED FROM STUDENT LOG]',(r.stdout+r.stderr).decode()));srv.wait(timeout=5)
   logs.append({'version':version,'port':port,'clientReturnCode':r.returncode,'serverReturnCode':srv.returncode})
  time.sleep(.4)
 finally:
  cap.terminate();cap.wait(timeout=5)
  if not (out/'tls-metadata-supplement.pcapng').exists() or (out/'tls-metadata-supplement.pcapng').stat().st_size<100:raise RuntimeError('Capture missing')
  for srv in servers:
   if srv.poll() is None:srv.terminate();srv.wait()
(out/'generation-execution.json').write_text(json.dumps({'commandsActuallyExecuted':True,'observedAt':'host loopback lo','opensslVersion':run(['openssl','version']).stdout.decode().strip(),'sessions':logs,'privateKeyPublished':False,'newCaptureVariableBytes':True},indent=2))
