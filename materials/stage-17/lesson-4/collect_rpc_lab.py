#!/usr/bin/env python3
"""Real IPv4 loopback SMB2/SCMR lab; inert responder NEVER controls OS services.
Requires Impacket 0.13.0. The StartService request intentionally receives no RPC reply.
Use a NEW output directory; tcpdump records only the dedicated loopback SMB port.
"""
import pathlib,sys,tempfile,time,subprocess,signal,json,hashlib,datetime
from multiprocessing import Process
from impacket.smbserver import SimpleSMBServer
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import scmr,rpcrt,transport
from impacket.dcerpc.v5.dtypes import NULL
PORT=17454
MANAGER=b'\0\0\0\0'+b'M'*16
SERVICE=b'\0\0\0\0'+b'S'*16
class InertSCMR(rpcrt.DCERPCServer):
 def __init__(self):
  super().__init__();self.daemon=True
  self.addCallbacks(('367ABB81-9844-35F1-AD32-98F038001003','2.0'),'\\PIPE\\svcctl',{15:self.manager,16:self.service,6:self.query,19:self.start_request})
 def processRequest(self,data):
  a=super().processRequest(data)
  if a is not None and a['type']==rpcrt.MSRPC_RESPONSE:
   a['cancel_count']=0;a['padding']=0;a['alloc_hint']=len(a['pduData'])
  return a
 def manager(self,data):
  scmr.ROpenSCManagerW(data);a=scmr.ROpenSCManagerWResponse();a['lpScHandle']=MANAGER;a['ErrorCode']=0;return a.getData()
 def service(self,data):
  q=scmr.ROpenServiceW(data);assert q['hSCManager']==MANAGER and q['lpServiceName'].rstrip('\0')=='AcademyExampleSvc'
  a=scmr.ROpenServiceWResponse();a['lpServiceHandle']=SERVICE;a['ErrorCode']=0;return a.getData()
 def query(self,data):
  q=scmr.RQueryServiceStatus(data);assert q['hService']==SERVICE
  a=scmr.RQueryServiceStatusResponse();a['lpServiceStatus']['dwServiceType']=16;a['lpServiceStatus']['dwCurrentState']=1;a['lpServiceStatus']['dwControlsAccepted']=0;a['lpServiceStatus']['dwWin32ExitCode']=0;a['lpServiceStatus']['dwServiceSpecificExitCode']=0;a['lpServiceStatus']['dwCheckPoint']=0;a['lpServiceStatus']['dwWaitHint']=0;a['ErrorCode']=0;return a.getData()
 def start_request(self,data):
  q=scmr.RStartServiceW(data);assert q['hService']==SERVICE
  # Deliberately hold response until parent stops this isolated process. No OS action.
  time.sleep(120)
def serve(path):
 rpc=InertSCMR();rpc.start()
 s=SimpleSMBServer(listenAddress='127.0.0.1',listenPort=PORT);s.addShare('DATA',path,'Inert Academy lab');s.setSMB2Support(True);s.registerNamedPipe('svcctl',('127.0.0.1',rpc.getListenPort()));s.start()
def main():
 if len(sys.argv)!=2:raise SystemExit('Usage: python collect_rpc_lab.py NEW_OUTPUT_DIRECTORY')
 out=pathlib.Path(sys.argv[1]);out.mkdir();started=datetime.datetime.now(datetime.timezone.utc).isoformat()
 with tempfile.TemporaryDirectory(prefix='academy-scmr-inert-') as td:
  pathlib.Path(td,'inventory.txt').write_text('Academy inert service correlation lab. No executable payload.\n')
  server=Process(target=serve,args=(td,));server.start();time.sleep(1)
  log=open(out/'capture.stderr.txt','w');cap=subprocess.Popen(['tcpdump','-i','lo','-U','-s','0','-w',str(out/'practice.pcap'),'tcp port '+str(PORT)],stdout=log,stderr=log);time.sleep(1)
  try:
   c=SMBConnection('ACADEMY','127.0.0.1',sess_port=PORT,preferredDialect=0x0202);c.login('','','');listing=c.listPath('DATA','*');assert any(i.get_longname()=='inventory.txt' for i in listing)
   t=transport.SMBTransport('127.0.0.1',PORT,filename='\\svcctl',smb_connection=c);d=t.get_dce_rpc();d.connect();d.bind(scmr.MSRPC_UUID_SCMR)
   manager=scmr.hROpenSCManagerW(d)['lpScHandle'];assert manager==MANAGER
   service=scmr.hROpenServiceW(d,manager,'AcademyExampleSvc\0')['lpServiceHandle'];assert service==SERVICE
   status=scmr.hRQueryServiceStatus(d,service);assert status['lpServiceStatus']['dwCurrentState']==1 and status['ErrorCode']==0
   q=scmr.RStartServiceW();q['hService']=service;q['argc']=0;q['argv']=NULL;d.call(q.opnum,q);time.sleep(2)
   # Do not recv: capture stops after real outbound start request, before any RPC response.
  finally:
   cap.send_signal(signal.SIGINT);cap.wait(timeout=10);log.close();server.terminate();server.join(timeout=5)
  (out/'collection.json').write_text(json.dumps({'kind':'actual Academy loopback capture of inert synthetic SCMR responder; NOT Windows, case evidence, or OS service execution','startedUTC':started,'endedUTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'interface':'lo','address':'127.0.0.1','port':PORT,'protocol':'SMB2.0.2','share':'DATA','namedPipe':'svcctl','interfaceUUID':'367abb81-9844-35f1-ad32-98f038001003','interfaceVersion':'2.0','assertedOperations':['DATA directory listing','SCMR manager handle','same manager handle opens named service','same service handle queried STOPPED','same service handle sent StartService request; no RPC receive performed'],'noOSServiceActions':True,'pcapSha256':hashlib.sha256((out/'practice.pcap').read_bytes()).hexdigest()},indent=2))
if __name__=='__main__':main()
