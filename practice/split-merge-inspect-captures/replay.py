from pathlib import Path
import subprocess,sys,json,hashlib,shutil,csv,struct,platform
base=Path(__file__).resolve().parent
out=Path(sys.argv[1]).resolve() if len(sys.argv)==2 else None
if out is None:raise SystemExit('Usage: python3 replay.py NEW_OUTPUT_DIRECTORY')
if out.exists():raise SystemExit('REFUSED: output already exists')
out.mkdir(parents=True); (out/'originals').mkdir();(out/'working').mkdir();(out/'working/chunks').mkdir()
logs=[]
def run(args):
 p=subprocess.run(args,capture_output=True,text=True);logs.append({'argv':args,'exitCode':p.returncode,'stdout':p.stdout,'stderr':p.stderr});
 if p.returncode:raise RuntimeError(str(logs[-1]))
 return p.stdout
try:
 for tool in ['capinfos','editcap','mergecap','tshark']:run([tool,'--version'])
 run([sys.executable,str(base/'offline-builder.py'),'--spec',str(base/'fixture-spec.json'),'--output',str(out/'master.pcap')])
 for name,sel in [('A',['1-5','7']),('B',['3-4','6','8-10'])]:
  original=out/'originals'/('sim-sensor-'+name+'.pcap');run(['editcap','-r','-F','pcap',str(out/'master.pcap'),str(original),*sel]);shutil.copy2(original,out/'working'/original.name)
 a=str(out/'working/sim-sensor-A.pcap');b=str(out/'working/sim-sensor-B.pcap')
 run(['editcap','-c','2',a,str(out/'working/chunks/syn-A.pcap')]);run(['editcap','-A','2025-05-06 12:00:02+00:00','-B','2025-05-06 12:00:05+00:00',a,str(out/'working/syn-A-window.pcap')]);run(['mergecap','-w',str(out/'working/merged.pcapng'),a,b])
 captures=sorted(p for p in out.rglob('*') if p.suffix in ('.pcap','.pcapng'))
 inventory=[]
 for p in captures:
  raw=run(['tshark','-r',str(p),'-T','fields','-e','frame.number','-e','frame.time_epoch','-e','ip.src','-e','ip.dst','-e','udp.payload']);count=len(raw.strip().splitlines());info=run(['capinfos','-c','-a','-e','-o',str(p)]);inventory.append({'path':str(p.relative_to(out)),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'frames':count,'packets':raw,'capinfos':info})
 counts={x['path']:x['frames'] for x in inventory};assert counts['originals/sim-sensor-A.pcap']==6 and counts['originals/sim-sensor-B.pcap']==6 and counts['working/merged.pcapng']==12 and counts['working/syn-A-window.pcap']==3
 assert sum(v for n,v in counts.items() if n.startswith('working/chunks/'))==6
 for name in ('A','B'):assert (out/'originals'/('sim-sensor-'+name+'.pcap')).read_bytes()==(out/'working'/('sim-sensor-'+name+'.pcap')).read_bytes()
 (out/'execution.json').write_text(json.dumps({'actualPlatform':platform.platform(),'runtimeSystem':platform.system(),'pythonVersion':platform.python_version(),'scope':'CLI execution only; native GUI evidence separate','commands':logs,'captures':inventory,'assertions':'6+6=12; three two-packet chunks; exclusive-stop window3; working copies byte-identical; no deduplication'},indent=2))
finally:
 (out/'commands.json').write_text(json.dumps(logs,indent=2))
