#!/usr/bin/env python3
"""Collect real SMB2 client/server traffic restricted to IPv4 loopback, ephemeral lab directories."""
import tempfile,pathlib,subprocess,sys,time,signal,json,hashlib,os
from impacket.smbserver import SimpleSMBServer
from impacket.smbconnection import SMBConnection
from multiprocessing import Process

def serve(path,port):
 s=SimpleSMBServer(listenAddress='127.0.0.1',listenPort=port);s.addShare('TRAINING',path,'Academy supplemental practice');s.setSMB2Support(True);s.start()
def main():
 if len(sys.argv)!=2:raise SystemExit('Usage: sudo venv/bin/python collect_lab.py NEW_OUTPUT_DIRECTORY')
 out=pathlib.Path(sys.argv[1]);out.mkdir();port=17452
 with tempfile.TemporaryDirectory(prefix='academy-smb-') as td:
  seed=b'Academy ordinary SMB read practice.\n';upload=b'Academy ordinary SMB write practice.\n';pathlib.Path(td,'lab-readme.txt').write_bytes(seed)
  server=Process(target=serve,args=(td,port));server.start();time.sleep(1)
  log=open(out/'capture.stderr.txt','w');cap=subprocess.Popen(['tcpdump','-i','lo','-U','-s','0','-w',str(out/'practice.pcap'),'tcp port '+str(port)],stderr=log,stdout=log);time.sleep(1)
  try:
   c=SMBConnection('ACADEMY','127.0.0.1',sess_port=port,preferredDialect=0x0202);c.login('','','');data=[];c.getFile('TRAINING','lab-readme.txt',data.append);assert b''.join(data)==seed
   import io
   c.putFile('TRAINING','lab-upload.txt',io.BytesIO(upload).read);assert pathlib.Path(td,'lab-upload.txt').read_bytes()==upload;c.logoff();c.close();time.sleep(1)
  finally:
   cap.send_signal(signal.SIGINT);cap.wait(timeout=10);log.close();server.terminate();server.join(timeout=5)
  (out/'collection.json').write_text(json.dumps({'kind':'actual Academy loopback lab, synthetic activity, not case evidence','interface':'lo','address':'127.0.0.1','port':port,'server':'Impacket SimpleSMBServer','client':'Impacket SMBConnection','protocol':'SMB2.0.2','share':'TRAINING','seedReadHex':seed.hex(),'uploadHex':upload.hex(),'readbackAndServerFileByteAssertions':True,'pcapSha256':hashlib.sha256((out/'practice.pcap').read_bytes()).hexdigest()},indent=2))
if __name__=='__main__':main()
