#!/usr/bin/env python3
"""Verify unchanged packaged Academy inputs, actual frame counts and saved comments offline."""
from pathlib import Path
import sys,subprocess,hashlib,json
if len(sys.argv)!=3:raise SystemExit('Usage: python verify_fixture.py KIT_DIRECTORY PATH_TO_TSHARK')
k=Path(sys.argv[1]);t=sys.argv[2];expected=json.loads((k/'expected-capture-sha256.json').read_text())
# Independent fixed identity pins prevent changing the capture manifest to bless new inputs.
if expected!={'practice.pcap': '92c4ba93b14ffc744e19c9371eb9546c6d16a0fac27c5dfcc935fff30901eae6', 'lesson5-synthetic-offline.pcapng': '1ecb7c5ab625d140f40d6d25efcd75d3348ca294a310df353c789cce422812cc', 'lesson5-commented.pcapng': '2805747b697a6841ddbb2b96f0e70efed460b900433af1f4fc870a3eba1fae06', 'lesson5-displayed.pcapng': '32ee7044e04de9c526e49ef3e6b7e33f4efc857bb481e5da6a49fd34a171da69', 'lesson5-captured.pcapng': '2805747b697a6841ddbb2b96f0e70efed460b900433af1f4fc870a3eba1fae06'}:raise SystemExit('Changed capture manifest')
for n,h in expected.items():
 if hashlib.sha256((k/n).read_bytes()).hexdigest()!=h:raise SystemExit('Changed capture: '+n)
def rows(n,f=''):
 a=[t,'-r',str(k/n)]+(['-Y',f] if f else [])+['-T','fields','-e','frame.number','-e','frame.comment'];p=subprocess.run(a,capture_output=True,text=True)
 if p.returncode:raise SystemExit(p.stderr)
 return p.stdout.splitlines()
for f,c in [('',6),('dns',2),('not dns',4),('udp',3),('tcp',3),('dns and udp',2),('_ws.malformed',0),('frame.cap_len < frame.len',0)]:
 if len(rows('lesson5-synthetic-offline.pcapng',f))!=c:raise SystemExit('Unexpected filtered count: '+f)
if any(x.split('\t',1)[1] for x in rows('lesson5-synthetic-offline.pcapng')):raise SystemExit('Learner input has packet comments')
for n,c in [('commented',6),('displayed',2),('captured',6)]:
 a=rows('lesson5-'+n+'.pcapng')
 if len(a)!=c:raise SystemExit('Unexpected export count '+n)
 comments=[x for x in a if 'Observed: DNS response 192.0.2.53 to 192.0.2.10' in x]
 if len(comments)!=1:raise SystemExit('Missing or duplicate expected packet comment '+n)
print(json.dumps({'verdict':'pass','identity':expected,'inputFrames':6,'dns':2,'notDns':4,'udp':3,'tcp':3,'commented':6,'displayed':2,'captured':6,'commentPersists':True,'platform':'actual invoked TShark; see delivered version log'}))
