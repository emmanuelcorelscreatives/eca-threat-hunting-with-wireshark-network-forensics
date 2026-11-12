#!/usr/bin/env python3
"""Prepare or verify the unchanged shared Academy DNS baseline. Sends no traffic."""
import argparse,hashlib,json,pathlib,subprocess,os,tempfile
ap=argparse.ArgumentParser();ap.add_argument('--source',default='shared-dns-baseline.pcap');ap.add_argument('--output',default='lab-reference.pcapng');ap.add_argument('--manifest',default='reference-checks.json');ap.add_argument('--check',action='store_true');a=ap.parse_args()
sha=lambda b:hashlib.sha256(b).hexdigest()
source=pathlib.Path(a.source);out=pathlib.Path(a.output);manifest=pathlib.Path(a.manifest)
expected='ff377b9bbe3c06df6ef68fe10b9beed6735421ae61b77330e59af574b0286e50'
if sha(source.read_bytes())!=expected:raise SystemExit('Source differs from the unchanged approved shared baseline')
def inspect(path):
 fields=['frame.number','frame.time_epoch','ip.src','ip.dst','dns.flags.response','dns.qry.name','dns.qry.type','dns.a'];cmd=['tshark','-n','-r',str(path),'-T','fields']
 for f in fields:cmd+=['-e',f]
 q=subprocess.run(cmd,capture_output=True,text=True,check=True);rows=[l.split('\t')for l in q.stdout.splitlines()];assert len(rows)==6
 return {'packetCount':len(rows),'firstEpoch':rows[0][1],'lastEpoch':rows[-1][1],'ipv4Endpoints':sorted({r[i]for r in rows for i in [2,3]}),'protocolTab':'IPv4','limitToDisplayedPackets':False,'displayFilter':'','fields':fields,'rows':rows}
if a.check:
 d=json.loads(manifest.read_text());assert d['sourceSha256']==sha(source.read_bytes());assert d['referenceSha256']==sha(out.read_bytes());assert d['observations']==inspect(out);assert inspect(source)==inspect(out);print('PASS: unchanged source, reference hash and every decoded row match');raise SystemExit()
if out.exists()or manifest.exists():raise SystemExit('Refusing existing output or manifest; use --check')
with tempfile.TemporaryDirectory(dir=str(out.parent))as temp:
 t=pathlib.Path(temp)/'reference.pcapng';subprocess.run(['editcap','-F','pcapng',str(source),str(t)],check=True);observed=inspect(t);assert observed==inspect(source)
 data=t.read_bytes();d={'synthetic':True,'source':str(source),'sourceSha256':expected,'reference':str(out),'referenceSha256':sha(data),'timezone':'UTC','firstUTC':'2026-11-11T00:00:00.000000Z','lastUTC':'2026-11-11T00:01:00.020000Z','observations':observed}
 with out.open('xb')as f:f.write(data)
 with manifest.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
print(json.dumps(d))
