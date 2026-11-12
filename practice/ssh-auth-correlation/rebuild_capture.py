"""Offline exact-byte reconstruction. Standard Python3 only; no network or keys."""
import argparse,hashlib,json,struct
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=Path);a=p.parse_args()
r=json.loads(Path(__file__).with_name('replay-records.json').read_text())
parts=[bytes.fromhex(r['globalHeaderHex'])]
for row in r['records']:
 h=bytes.fromhex(row['headerHex']);b=bytes.fromhex(row['packetHex'])
 assert len(h)==16 and struct.unpack('<IIII',h)[2]==len(b)
 assert hashlib.sha256(b).hexdigest()==row['packetSha256']
 parts.extend([h,b])
b=b''.join(parts);assert hashlib.sha256(b).hexdigest()==r['pcapSha256']
with a.output.open('xb') as f:f.write(b)
print(hashlib.sha256(b).hexdigest(),a.output)
