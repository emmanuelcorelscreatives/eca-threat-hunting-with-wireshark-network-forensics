"""Verify the exact synthetic lab without modifying its capture or spec."""
import argparse,hashlib,subprocess,tempfile,sys
from pathlib import Path
p=argparse.ArgumentParser(); p.add_argument('--tshark',default='tshark'); a=p.parse_args(); root=Path(__file__).resolve().parent
capture=root/'practice.pcap'; original=capture.read_bytes(); expected='610fd5d81606704845f97400c085fe49bba38be534111694998521159ec58a97'
if len(original)!=498 or hashlib.sha256(original).hexdigest()!=expected: raise SystemExit('Capture identity mismatch')
def fields(filter=None):
 cmd=[a.tshark,'-r',str(capture)]
 if filter is not None: cmd+=['-Y',filter]
 cmd+=['-T','fields','-e','frame.number']
 return subprocess.run(cmd,check=True,capture_output=True,text=True).stdout.splitlines()
if fields()!=['1','2','3','4','5','6']: raise SystemExit('Total frame order mismatch')
if fields('tcp')!=['2','4','6']: raise SystemExit('TCP selection mismatch')
if fields('_ws.malformed'): raise SystemExit('Malformed frame detected')
with tempfile.TemporaryDirectory(prefix='eca-selection-') as tmp:
 out=Path(tmp)/'rebuilt.pcap'
 subprocess.run([sys.executable,str(root/'offline-builder.py'),'--spec',str(root/'fixture-plan.json'),'--output',str(out)],check=True,capture_output=True)
 if out.read_bytes()!=original: raise SystemExit('Rebuilt capture differs')
if capture.read_bytes()!=original: raise SystemExit('Supplied capture changed')
print('PASS: 498 bytes; six frames; TCP frames 2,4,6; no malformed frames; identical offline rebuild; source unchanged')
