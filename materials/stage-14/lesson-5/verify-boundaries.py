"""Fail-closed verification of this exact Academy capture and authorized secrets.
No network activity. Requires Python3 and TShark; prints a derived report.
"""
import argparse,pathlib,hashlib,subprocess,json,sys

def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--manifest',type=pathlib.Path,required=True);ap.add_argument('--capture',type=pathlib.Path,required=True);ap.add_argument('--keylog',type=pathlib.Path,required=True);a=ap.parse_args();m=json.loads(a.manifest.read_text())
 for label,p in [('capture',a.capture),('keylog',a.keylog)]:
  if digest(p)!=m[label+'Sha256']:raise ValueError(label+' SHA256 mismatch')
 fields=['frame.number','frame.time_epoch','frame.len','ip.src','ip.dst','tcp.srcport','tcp.dstport','udp.srcport','udp.dstport','tcp.stream','udp.stream','_ws.col.Protocol','tls.handshake.extensions_alpn_str','http2.streamid','http2.headers.path','http2.headers.status','quic.stream.stream_id','http3.headers.path','http3.headers.status','http2.flags.end_stream','quic.stream.fin','tcp.seq','tcp.ack','tcp.len','tcp.flags.syn','tcp.flags.ack','tcp.analysis.retransmission','tcp.checksum.status','udp.checksum.status','_ws.expert.message']
 def read(with_keys):
  cmd=['tshark','-r',str(a.capture),'-d','tcp.port==18445,tls','-o','tcp.check_checksum:TRUE','-o','udp.check_checksum:TRUE','-T','fields','-E','separator=\t','-E','occurrence=a']
  if with_keys:cmd+=['-o','tls.keylog_file:'+str(a.keylog)]
  for f in fields:cmd+=['-e',f]
  r=subprocess.run(cmd,capture_output=True,text=True,check=True)
  return [dict(zip(fields,line.split('\t')))for line in r.stdout.splitlines()]
 before=read(False);after=read(True)
 def summary(rows):
  return {'frames':len(rows),'packetBytes':sum(int(r['frame.len'])for r in rows),'http2Frames':[int(r['frame.number'])for r in rows if r['http2.streamid']],'quicFrames':[int(r['frame.number'])for r in rows if 'QUIC'in r['_ws.col.Protocol']or 'HTTP3'in r['_ws.col.Protocol']],'http3Frames':[int(r['frame.number'])for r in rows if 'HTTP3'in r['_ws.col.Protocol']],'h2Paths':sorted({v for r in rows for v in r['http2.headers.path'].split(',')if v}),'h3Paths':sorted({v for r in rows for v in r['http3.headers.path'].split(',')if v}),'h2Statuses':sorted({v for r in rows for v in r['http2.headers.status'].split(',')if v}),'h3Statuses':sorted({v for r in rows for v in r['http3.headers.status'].split(',')if v})}
 b=summary(before);c=summary(after)
 assert c['frames']==m['expected']['frames'] and c['packetBytes']==m['expected']['packetBytes'],'capture totals'
 assert not b['http2Frames'] and not b['http3Frames'],'unexpected plaintext application'
 assert c['h2Paths']==['/alpha','/beta']and c['h3Paths']==['/delta','/gamma'],'missing request paths'
 assert c['h2Statuses']==['200']and c['h3Statuses']==['200'],'missing responses'
 assert set(v for r in after for v in r['http2.streamid'].split(',')if v)=={'0','1','3'},'h2 stream IDs'
 assert {'0','4'}<=set(v for r in after for v in r['quic.stream.stream_id'].split(',')if v),'h3 stream IDs'
 assert set(r['tcp.stream']for r in after if r['tcp.stream'])=={'0'},'TCP connection count'
 assert set(r['udp.stream']for r in after if r['udp.stream'])=={'0'},'UDP conversation count'
 # Scope stream association checks to actual decoded application frames, with both directions.
 for stream,path in [('1','/alpha'),('3','/beta')]:
  assert any(stream in r['http2.streamid'].split(',') and path in r['http2.headers.path'].split(',') and r['tcp.dstport']=='18445' for r in after),'h2 request association'
  assert any(stream in r['http2.streamid'].split(',') and '200'in r['http2.headers.status'].split(',') and r['tcp.srcport']=='18445' and 'True'in r['http2.flags.end_stream'].split(',')for r in after),'h2 response association'
 for stream,path in [('0','/gamma'),('4','/delta')]:
  assert any(stream in r['quic.stream.stream_id'].split(',') and path in r['http3.headers.path'].split(',') and r['udp.dstport']=='18446' for r in after),'h3 request association'
  assert any(stream in r['quic.stream.stream_id'].split(',') and '200'in r['http3.headers.status'].split(',') and r['udp.srcport']=='18446' and 'True'in r['quic.stream.fin'].split(',')for r in after),'h3 response association'
 assert any(r['tcp.flags.syn']=='True'and r['tcp.flags.ack']=='False'for r in after)and any(r['tcp.flags.syn']=='True'and r['tcp.flags.ack']=='True'for r in after),'opening TCP handshake'
 assert not any(r['tcp.analysis.retransmission'] for r in after),'unexpected retransmission'
 assert all(r['ip.src']==r['ip.dst']=='127.0.0.1' for r in after),'scope'
 assert all(float(after[i]['frame.time_epoch'])<=float(after[i+1]['frame.time_epoch'])for i in range(len(after)-1)),'timestamps'
 assert not any('Bad checksum'in r['_ws.expert.message']or 'Malformed'in r['_ws.expert.message'] for r in after),'checksum/malformed warning'
 print(json.dumps({'state':'PASS','captureSha256':digest(a.capture),'keylogSha256':digest(a.keylog),'tsharkVersion':subprocess.check_output(['tshark','--version'],text=True).splitlines()[0],'withoutKeys':b,'withKeys':c,'decodedWithKeys':after,'limitations':'Actual owned loopback lab; no historical incident, off-host loss, internet site, learner-own-capture, or other encrypted traffic inference. Stream 0 HTTP/2 is connection control. QUIC streams 2/3/6/7/10/11 are control/QPACK, not six web exchanges. Captured checksums are partial pseudo-header values from loopback offload; they are not wire-valid checksum proof. No malformed or bad-checksum warning is observed. TCP relative sequence/ACK fields are retained for inspection; no off-host transmission or loss claim. Capture integrity is SHA-bound.'},indent=2))
if __name__=='__main__':
 try:main()
 except Exception as e:print('FAIL: '+str(e),file=sys.stderr);sys.exit(1)
