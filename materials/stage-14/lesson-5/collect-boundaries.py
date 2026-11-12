"""Create real localhost h2/TLS and h3/QUIC traffic. Requires aioquic/h2; root tcpdump.
Refuses existing output; no external traffic. Private certificate remains in temporary dir.
"""
import asyncio, ssl, pathlib, tempfile, subprocess, signal, json, datetime
import h2.connection,h2.config,h2.events
from aioquic.asyncio import serve,connect,QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived,DataReceived
D=pathlib.Path(__file__).resolve().parent
LOG=[]
class H3(QuicConnectionProtocol):
 def __init__(self,*a,**kw):
  super().__init__(*a,**kw);self.http=H3Connection(self._quic);self.done=set();self.response=asyncio.Event()
 def quic_event_received(self,e):
  if isinstance(e,ProtocolNegotiated):LOG.append({'protocol':'h3','role':'client' if self._quic.configuration.is_client else 'server','negotiated_alpn':e.alpn_protocol})
  for ev in self.http.handle_event(e):
   if isinstance(ev,HeadersReceived):
    LOG.append({'protocol':'h3','stream':ev.stream_id,'headers':[(k.decode(),v.decode())for k,v in ev.headers],'role':'client' if self._quic.configuration.is_client else 'server'})
    if not self._quic.configuration.is_client:
     self.http.send_headers(ev.stream_id,[(b':status',b'200'),(b'content-type',b'text/plain')]);self.http.send_data(ev.stream_id,b'Academy isolated h3 response\n',end_stream=True);self.transmit()
   if isinstance(ev,DataReceived) and ev.stream_ended and self._quic.configuration.is_client:
    self.done.add(ev.stream_id)
    if len(self.done)==2:self.response.set()
async def main():
 for n in ['supplemental-boundaries.pcapng','supplemental-boundaries.keys','application-execution.json']:
  if (D/n).exists():raise RuntimeError('Refuse overwrite '+n)
 with tempfile.TemporaryDirectory(prefix='academy-boundaries-')as td:
  cert=td+'/cert.pem';priv=td+'/key.pem'
  subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',priv,'-out',cert,'-days','1','-subj','/CN=localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  keys=D/'supplemental-boundaries.keys';keys.touch(mode=0o600)
  sc=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);sc.load_cert_chain(cert,priv);sc.set_alpn_protocols(['h2']);sc.keylog_filename=str(keys)
  async def h2server(r,w):
   conn=h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False));conn.initiate_connection();w.write(conn.data_to_send())
   try:
    while b:=await r.read(65536):
     for ev in conn.receive_data(b):
      if isinstance(ev,h2.events.RequestReceived):
       LOG.append({'protocol':'h2','role':'server','stream':ev.stream_id,'headers':[(k.decode(),v.decode())for k,v in ev.headers]});conn.send_headers(ev.stream_id,[(b':status',b'200'),(b'content-type',b'text/plain')]);conn.send_data(ev.stream_id,b'Academy isolated h2 response\n',end_stream=True)
     w.write(conn.data_to_send());await w.drain()
   finally:w.close();await w.wait_closed()
  srv=await asyncio.start_server(h2server,'127.0.0.1',18445,ssl=sc)
  keyfile=open(keys,'a');qsc=QuicConfiguration(is_client=False,alpn_protocols=['h3'],secrets_log_file=keyfile);qsc.load_cert_chain(cert,priv);qsrv=await serve('127.0.0.1',18446,configuration=qsc,create_protocol=H3)
  cap=subprocess.Popen(['dumpcap','-i','lo','-f','tcp port 18445 or udp port 18446','-w','-'],stdout=open(D/'supplemental-boundaries.pcapng','xb'),stderr=open(D/'capture.stderr.txt','w'))
  await asyncio.sleep(1)
  cc=ssl.create_default_context();cc.check_hostname=False;cc.verify_mode=ssl.CERT_NONE;cc.set_alpn_protocols(['h2'])
  r,w=await asyncio.open_connection('127.0.0.1',18445,ssl=cc,server_hostname='localhost');LOG.append({'protocol':'h2','role':'client','negotiated_alpn':w.get_extra_info('ssl_object').selected_alpn_protocol()})
  conn=h2.connection.H2Connection();conn.initiate_connection()
  for sid,path in [(1,'/alpha'),(3,'/beta')]:conn.send_headers(sid,[(b':method',b'GET'),(b':scheme',b'https'),(b':authority',b'localhost'),(b':path',path.encode())],end_stream=True)
  w.write(conn.data_to_send());await w.drain();done=set()
  while len(done)<2:
   b=await asyncio.wait_for(r.read(65536),10)
   for ev in conn.receive_data(b):
    if isinstance(ev,h2.events.ResponseReceived):LOG.append({'protocol':'h2','role':'client','stream':ev.stream_id,'headers':[(k.decode(),v.decode())for k,v in ev.headers]})
    if isinstance(ev,h2.events.StreamEnded):done.add(ev.stream_id)
   w.write(conn.data_to_send());await w.drain()
  w.close();await w.wait_closed();await asyncio.sleep(.3)
  qc=QuicConfiguration(is_client=True,alpn_protocols=['h3'],verify_mode=ssl.CERT_NONE,server_name='localhost')
  async with connect('127.0.0.1',18446,configuration=qc,create_protocol=H3)as q:
   for path in ['/gamma','/delta']:
    sid=q._quic.get_next_available_stream_id();q.http.send_headers(sid,[(b':method',b'GET'),(b':scheme',b'https'),(b':authority',b'localhost'),(b':path',path.encode())],end_stream=True)
   q.transmit();await asyncio.wait_for(q.response.wait(),15)
  await asyncio.sleep(.5);qsrv.close();srv.close();await srv.wait_closed();keyfile.close();cap.send_signal(signal.SIGINT);cap.wait(timeout=10)
  if cap.returncode or (D/'supplemental-boundaries.pcapng').stat().st_size<100:raise RuntimeError('Capture failed')
  (D/'application-execution.json').write_text(json.dumps({'collectedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'Actual controlled Academy localhost sessions, not historical incident or learner-owned capture','events':LOG},indent=2))
asyncio.run(main())
