#!/usr/bin/env python3
"""Offline deterministic construction of separate synthetic sensor files. No network I/O."""
import argparse,json
from pathlib import Path
import importlib.util
s=importlib.util.spec_from_file_location('builder',Path(__file__).with_name('offline-builder.py'));b=importlib.util.module_from_spec(s);s.loader.exec_module(b)
p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args()
master=json.loads(Path(__file__).with_name('executed-fixture-spec.json').read_text());a.out.mkdir(parents=True,exist_ok=True)
for name,start in [('ab',0),('bc',10)]:
 spec=dict(master,events=master['events'][start:start+10]);data=b.generate(spec)
 with (a.out/(name+'.pcap')).open('xb') as f:f.write(data)
 print(name,len(data))
