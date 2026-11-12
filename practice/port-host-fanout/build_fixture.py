#!/usr/bin/env python3
"""Offline CSV builder. No network operations; refuses overwrite."""
import argparse,csv,json
from pathlib import Path
from offline_builder import generate
p=argparse.ArgumentParser();p.add_argument('--plan',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
events=[]
for x in csv.DictReader(a.plan.open()):
 events.append(dict(timestamp=x['timestamp_utc'],kind='tcp',src=x['src_ip'],dst=x['dst_ip'],sport=int(x['src_port']),dport=int(x['dst_port']),flags=x['tcp_flags'],seq=int(x['seq']),ack=int(x['ack'])))
with a.output.open('xb') as f:f.write(generate(dict(version=1,synthetic=True,events=events)))
