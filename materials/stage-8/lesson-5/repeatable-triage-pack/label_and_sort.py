#!/usr/bin/env python3
"""Label per-source CSVs and sort a review copy without changing raw inputs."""
import argparse,csv,json
from pathlib import Path
from decimal import Decimal
p=argparse.ArgumentParser();p.add_argument('--manifest',required=True,type=Path);p.add_argument('--source-log',required=True,type=Path);p.add_argument('--csv-dir',required=True,type=Path);p.add_argument('--labeled-dir',required=True,type=Path);p.add_argument('--out',required=True,type=Path);a=p.parse_args()
manifest=list(csv.DictReader(a.manifest.open(newline='')));logs=json.loads(a.source_log.read_text());rows=[];seen=set();fields=['frame.number','frame.time_epoch','frame.len','ip.src','ip.dst'];header=['source_id','original_input_filename']+fields
if len({m['source_id']for m in manifest})!=len(manifest):raise ValueError('Duplicate manifest source')
for m in manifest:
 source=m['source_id']
 if source not in ['point-a','point-b','point-c']:raise ValueError('Unknown source')
 log=next(x for x in logs if x['source_id']==source)
 if log['original_path']!=m['original_path']or log['original_sha256']!=log['working_sha256']:raise ValueError('Source provenance mismatch')
 reader=csv.DictReader((a.csv_dir/(source+'.csv')).open(newline=''))
 if reader.fieldnames!=fields:raise ValueError('Unexpected CSV header')
 local=[]
 for r in reader:
  key=(source,r['frame.number'])
  if key in seen or not r['frame.number'].isdigit()or int(r['frame.number'])<1:raise ValueError('Duplicate/invalid original reference')
  if not Decimal(r['frame.time_epoch']).is_finite():raise ValueError('Invalid time')
  seen.add(key);r={'source_id':source,'original_input_filename':Path(m['original_path']).name,**r};local.append(r);rows.append(r)
 a.labeled_dir.mkdir(parents=True,exist_ok=True)
 with(a.labeled_dir/(source+'.csv')).open('x',newline='')as f:
  writer=csv.DictWriter(f,fieldnames=header);writer.writeheader();writer.writerows(local)
rows.sort(key=lambda r:(Decimal(r['frame.time_epoch']),r['source_id'],int(r['frame.number'])))
a.out.parent.mkdir(parents=True,exist_ok=True)
with a.out.open('x',newline='')as f:
 writer=csv.DictWriter(f,fieldnames=header);writer.writeheader();writer.writerows(rows)
print(json.dumps({'retainedRows':len(rows),'uniqueSourceFramePairs':len(seen),'inputFilesPreserved':True,'epochStringsPreserved':True,'clockSynchronizationEstablished':False}))
