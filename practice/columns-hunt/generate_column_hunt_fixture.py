#!/usr/bin/env python3
"""Offline version1 replacement: consumes delivered column-hunt-spec.json; sends no traffic."""
import argparse,importlib.util,json,hashlib,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--output',type=Path);p.add_argument('--verify',type=Path);p.add_argument('--expected',type=Path);p.add_argument('--tshark',default='tshark');a=p.parse_args();root=Path(__file__).resolve().parent
if bool(a.output)==bool(a.verify):p.error('Choose --output or --verify')
if a.output:
 s=importlib.util.spec_from_file_location('builder',root/'offline-builder.py');b=importlib.util.module_from_spec(s);s.loader.exec_module(b);data=b.generate(json.loads((root/'column-hunt-spec.json').read_text()));a.output.parent.mkdir(parents=True,exist_ok=True)
 with a.output.open('xb') as f:f.write(data)
 print(json.dumps({'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'synthetic':True}))
else:
 if not a.expected:p.error('--expected required')
 e=json.loads(a.expected.read_text());data=a.verify.read_bytes()
 if hashlib.sha256(data).hexdigest()!=e['sha256']:raise SystemExit('FAIL capture SHA256')
 def fields(filt,names):
  args=[a.tshark,'-n','-r',str(a.verify),'-Y',filt,'-T','fields','-E','occurrence=a','-E','aggregator=,']
  for n in names:args+=['-e',n]
  return subprocess.run(args,capture_output=True,text=True,check=True).stdout.strip().splitlines()
 checks=[fields('frame', ['frame.number'])==[str(n) for n in range(1,21)],fields('frame.number == 19',['tls.handshake.extensions_server_name'])==['tls.academy.test'],fields('frame.number == 20',['dns.resp.name','dns.a'])==['repeat.academy.test,repeat.academy.test\t198.51.100.50,198.51.100.51'],fields('frame.number == 8',['http.host','http.request.method'])==['view.academy.test\tGET'],fields('_ws.malformed',['frame.number'])==[]]
 if not all(checks):raise SystemExit('FAIL decoded assertions')
 print(json.dumps({'verdict':'pass','checks':len(checks),'sha256':e['sha256']}))
