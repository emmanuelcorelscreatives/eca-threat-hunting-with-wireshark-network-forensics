"""Run documented rejection probes only in a temporary working directory."""
import csv,io,json,pathlib,subprocess,tempfile
root=pathlib.Path(__file__).resolve().parent;tests=[]
with tempfile.TemporaryDirectory() as td:
 td=pathlib.Path(td);raw=(root/'practice.pcap').read_bytes()
 for name,data in [('truncated',raw[:-5]),('changed',raw.replace(b'pending',b'changed')),('empty',b'')]:
  path=td/(name+'.pcap');path.write_bytes(data);cmd=['python3',str(root/'check_fixture.py'),'--inventory',str(root/'inventory.tsv'),'--events',str(root/'events.tsv'),'--pcap',str(path)];r=subprocess.run(cmd,capture_output=True,text=True)
  if not r.returncode:raise RuntimeError('Bad capture accepted')
  tests.append({'probe':name,'mutation':{'truncated':'remove last five bytes','changed':'replace pending with changed in query name','empty':'zero bytes'}[name],'command':cmd,'returncode':r.returncode,'stderr':r.stderr})
 for name,column,value in [('wrong-response-port','dst_port','53199'),('orphan-response','txid','9999')]:
  rows=list(csv.DictReader(open(root/'events.tsv'),delimiter='\t'));rows[1][column]=value;f=td/(name+'.tsv')
  with f.open('w') as stream:w=csv.DictWriter(stream,fieldnames=rows[0],delimiter='\t');w.writeheader();w.writerows(rows)
  cmd=['python3',str(root/'build_fixture.py'),'--inventory',str(root/'inventory.tsv'),'--events',str(f),'--out',str(td/(name+'.pcap'))];r=subprocess.run(cmd,capture_output=True,text=True)
  if not r.returncode:raise RuntimeError('Bad event accepted')
  tests.append({'probe':name,'mutation':{'row':2,'column':column,'newValue':value},'command':cmd,'returncode':r.returncode,'stderr':r.stderr})
 cmd=['python3',str(root/'build_fixture.py'),'--inventory',str(root/'inventory.tsv'),'--events',str(root/'events.tsv'),'--out',str(root/'practice.pcap')];r=subprocess.run(cmd,capture_output=True,text=True)
 if not r.returncode:raise RuntimeError('Existing output overwritten')
 tests.append({'probe':'existing-output','command':cmd,'returncode':r.returncode,'stderr':r.stderr})
print(json.dumps({'state':'PASS','tests':tests},indent=2))
