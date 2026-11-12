#!/usr/bin/env python3
"""Produce six-column exports in a NEW directory, refusing overwrite. Offline only."""
import argparse,csv,hashlib,io,json,shutil,subprocess
from pathlib import Path
FIELDS=['frame.number','frame.time_epoch','ip.src','ip.dst','dns.qry.name','dns.a']
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output-dir',type=Path,required=True);p.add_argument('--tshark',default='tshark');a=p.parse_args();root=Path(__file__).resolve().parent
 registry=subprocess.run([a.tshark,'-G','fields'],capture_output=True,text=True,check=True).stdout
 found={line.split('\t')[2]for line in registry.splitlines()if line.startswith('F\t')}
 if not set(FIELDS)<=found:raise ValueError('Installed TShark missing exact required field')
 # Validate mandatory inputs before creating outputs.
 for n in ['practice.pcap','repeated-a.pcap']:
  if not (root/n).is_file():raise ValueError('Missing source '+n)
 a.output_dir.mkdir(parents=False,exist_ok=False)
 (a.output_dir/'working-copy.pcap').write_bytes((root/'practice.pcap').read_bytes())
 records=[]
 for label,cap,occ in [('timeline',a.output_dir/'working-copy.pcap','a'),('repeated-all',root/'repeated-a.pcap','a'),('repeated-first',root/'repeated-a.pcap','f'),('repeated-last',root/'repeated-a.pcap','l')]:
  argv=[a.tshark,'-r',str(cap),'-Y','dns','-T','fields']+sum((['-e',f]for f in FIELDS),[])+['-E','header=y','-E','separator=,','-E','quote=d','-E','occurrence='+occ,'-E','aggregator=;']
  p=subprocess.run(argv,capture_output=True,check=True);rows=list(csv.reader(io.StringIO(p.stdout.decode())))
  if rows[0]!=FIELDS or any(len(row)!=6 for row in rows):raise ValueError('CSV structure invalid')
  with (a.output_dir/(label+'.csv')).open('xb')as f:f.write(p.stdout)
  (a.output_dir/(label+'.stderr.txt')).write_bytes(p.stderr)
  records.append(dict(argv=argv,captureSha256=hashlib.sha256(cap.read_bytes()).hexdigest(),rows=len(rows)-1,stdoutSha256=hashlib.sha256(p.stdout).hexdigest()))
 (a.output_dir/'run.json').write_text(json.dumps(dict(toolVersion=subprocess.run([a.tshark,'-v'],capture_output=True,text=True,check=True).stdout,records=records),indent=2)+'\n')
 print(json.dumps(dict(outputDirectory=str(a.output_dir),exports=len(records))))
if __name__=='__main__':main()
