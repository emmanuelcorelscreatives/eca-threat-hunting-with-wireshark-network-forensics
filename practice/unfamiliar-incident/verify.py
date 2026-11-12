#!/usr/bin/env python3
import json,hashlib,subprocess,pathlib
k=pathlib.Path(__file__).resolve().parent
v=json.loads((k/'actual-verification.json').read_text()); c=json.loads((k/'case-bundle.json').read_text())
assert hashlib.sha256((k/'practice.pcap').read_bytes()).hexdigest()==c['captureSha256']==v['captureSha256']
assert hashlib.sha256((k/'corroborating-records.jsonl').read_bytes()).hexdigest()==c['recordsSha256']
for x in (k/'corroborating-records.jsonl').read_text().splitlines():json.loads(x)
for f,frames in v['selections'].items():
 p=subprocess.run(['tshark','-r',str(k/'practice.pcap'),'-Y',f,'-T','fields','-e','frame.number'],check=True,capture_output=True,text=True)
 assert p.stdout.split()==frames,f
print('PASS exact hashes, JSONL and all filter frame selections')
