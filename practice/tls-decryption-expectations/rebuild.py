"""Offline Academy fixture byte replay. No network, no overwrites."""
import sys,json,base64,hashlib
from pathlib import Path
src=Path(__file__).parent
out=Path(sys.argv[1])
if out.exists():raise SystemExit("Refusing existing output directory")
records=json.loads((src/'replay-records.json').read_text())
for name in records:
 if Path(name).name!=name:raise SystemExit("Unsafe record name")
out.mkdir()
for name,value in records.items():
 with (out/name).open('xb') as f:f.write(base64.b64decode(value,validate=True))
print(json.dumps({n:hashlib.sha256((out/n).read_bytes()).hexdigest()for n in records},indent=2))
