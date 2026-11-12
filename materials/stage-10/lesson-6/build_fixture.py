#!/usr/bin/env python3
"""Collect owned local TLS traffic. Never overwrite an existing output directory."""
import argparse,datetime,hashlib,json,os,pathlib,socket,ssl,subprocess,tempfile,threading,time
p=argparse.ArgumentParser();p.add_argument('--output',required=True);a=p.parse_args();out=pathlib.Path(a.output);out.mkdir(parents=True,exist_ok=False)
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
meta={'synthetic':True,'kind':'Actual Academy loopback capture of scripted local TLS 1.3 traffic, not incident evidence','host_id':'academy-loopback-host','capture_point':'Linux lo; both endpoints are the same owned host','mapping':{'client':'127.0.0.1','peer':'127.0.0.1','distinguish_by':'TCP port, not IP direction'},'clock':'Application anchors and capture timestamps use the same host clock; no independent clock-offset measurement','known_gaps':['No external network, DNS, ECH, browser or endpoint telemetry is captured','Capture covers only the scripted sessions; it cannot establish any real case'],'scenarios':[]}
with tempfile.TemporaryDirectory(prefix='academy-https-') as tmp:
 cert=pathlib.Path(tmp)/'cert.pem';key=pathlib.Path(tmp)/'key.pem'
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=academy.test'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 for role,port,name in [('candidate',18443,'candidate.academy.test'),('updater',18444,'updater.academy.test')]:
  # Bind first: port collisions fail closed before capture/traffic.
  listener=socket.socket();listener.bind(('127.0.0.1',port));listener.listen(1);listener.settimeout(8)
  errors=[];receipt={};server_ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);server_ctx.minimum_version=server_ctx.maximum_version=ssl.TLSVersion.TLSv1_3;server_ctx.load_cert_chain(cert,key)
  def serve():
   try:
    raw,_=listener.accept()
    with server_ctx.wrap_socket(raw,server_side=True) as conn:
     request=conn.recv(4096);receipt['server_received_request_bytes']=len(request)
     body=(b'INERT ACADEMY COMPARISON DATA\n'*80);conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body)
   except Exception as e:errors.append(repr(e))
   finally:listener.close()
  capture=subprocess.Popen(['tcpdump','-i','lo','-U','-s','0','-w',str(out/(role+'.pcap')),'tcp','port',str(port)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
  try:
   time.sleep(.6)
   if capture.poll() is not None:raise RuntimeError('tcpdump did not remain alive')
   t=threading.Thread(target=serve);t.start();anchor=utc();time.sleep(.15)
   ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE;ctx.minimum_version=ctx.maximum_version=ssl.TLSVersion.TLSv1_3
   with socket.create_connection(('127.0.0.1',port),timeout=8) as raw:
    with ctx.wrap_socket(raw,server_hostname=name) as c:
     receipt['negotiated_tls']=c.version();c.sendall(b'GET /inert-training-response HTTP/1.1\r\nHost: '+name.encode()+b'\r\nConnection: close\r\n\r\n');data=b''
     while True:
      b=c.recv(8192)
      if not b:break
      data+=b
     receipt['client_received_http_bytes']=len(data);receipt['client_saved_object']=False
   t.join(10)
   if t.is_alive() or errors:raise RuntimeError(str(errors or 'server timeout'))
   time.sleep(.6)
  finally:
   capture.send_signal(2);_,log=capture.communicate(timeout=10);(out/(role+'-tcpdump.txt')).write_text(log);listener.close()
  if capture.returncode!=0:raise RuntimeError('capture failed')
  meta['scenarios'].append({'role':role,'file':role+'.pcap','port':port,'sni':name,'simulated_report_anchor_utc':anchor,'collection_finished_utc':utc(),'control_label_source':'Scripted Academy provenance; updater is known ordinary by construction, not by packet inference','receipt':receipt})
(out/'fixture.json').write_text(json.dumps(meta,indent=2)+'\n')
anchor=meta['scenarios'][0]['simulated_report_anchor_utc'];events=[{'synthetic':True,'host_id':meta['host_id'],'timestamp_utc':anchor,'event_type':'artifact-record','artifact_id':'mock-artifact-A','source':'Authored mock endpoint excerpt; not collected telemetry'},{'synthetic':True,'host_id':meta['host_id'],'timestamp_utc':anchor,'event_type':'process-creation','process_name':'ordinary-helper','linked_artifact_id':None,'source':'Authored incomplete mock endpoint excerpt; no link to mock-artifact-A'}]
(out/'endpoint.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))
print(json.dumps({'state':'COLLECTED','directory':str(out),'private_keys_published':False}))
