"""Reconstruct reviewed synthetic PCAP bytes offline, refusing existing output."""
import argparse,base64,hashlib,json,pathlib
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output-dir',required=True,type=pathlib.Path);a=p.parse_args()
records=json.loads((pathlib.Path(__file__).parent/'replay-records.json').read_text());decoded={}
for name,item in records.items():
 if name not in {'dns.pcap','tls.pcap'}:raise ValueError('Invalid capture name')
 data=base64.b64decode(item['base64'],validate=True)
 if hashlib.sha256(data).hexdigest()!=item['sha256']:raise ValueError('Capture hash mismatch')
 decoded[name]=data
a.output_dir.mkdir() # Atomic refusal of an existing directory, including empty ones.
for name,data in decoded.items():
 with (a.output_dir/name).open('xb') as f:f.write(data)
print(json.dumps({n:hashlib.sha256(b).hexdigest() for n,b in decoded.items()}))
