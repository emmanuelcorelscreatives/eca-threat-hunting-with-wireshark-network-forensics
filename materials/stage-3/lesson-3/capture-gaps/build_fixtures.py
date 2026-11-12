#!/usr/bin/env python3
"""Generate all synthetic comparisons locally; refuse to overwrite outputs."""
import argparse, importlib.util, json, hashlib
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
base=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('builder',base/'offline_builder.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
rows=[]
for name in ['session-complete','session-truncated','session-one-sided']:
 data=m.generate(json.loads((base/(name+'.json')).read_text()));rows.append((a.output/(name+'.pcap'),data))
if any(path.exists() for path,data in rows):raise SystemExit('Refusing existing output; choose a fresh directory')
a.output.mkdir(parents=True,exist_ok=True)
for path,data in rows:
 with path.open('xb') as f:f.write(data)
 print(json.dumps({'file':str(path),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'synthetic':True}))
