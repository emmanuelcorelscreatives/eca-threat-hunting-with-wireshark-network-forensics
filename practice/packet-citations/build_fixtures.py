#!/usr/bin/env python3
"""Build synthetic packet-citation fixtures offline in a NEW output directory."""
from pathlib import Path
import argparse,subprocess,os,json,hashlib,sys
p=argparse.ArgumentParser();p.add_argument('--output',required=True,type=Path);a=p.parse_args();r=Path(__file__).resolve().parent
a.output.mkdir(parents=True,exist_ok=False)
def tool(n):return str(Path(os.environ['WIRESHARK_BIN_DIR'])/n) if os.environ.get('WIRESHARK_BIN_DIR') and (Path(os.environ['WIRESHARK_BIN_DIR'])/n).is_file() else n
commands=[]
def run(args):
 c=[str(x) for x in args];z=subprocess.run(c,capture_output=True,text=True,check=True);commands.append({'argv':c,'returncode':z.returncode,'stdout':z.stdout,'stderr':z.stderr})
run([sys.executable,r/'offline-builder.py','--spec',r/'original-a-spec.json','--output',a.output/'original-a.pcap'])
run([sys.executable,r/'offline-builder.py','--spec',r/'original-b-dns-spec.json','--output',a.output/'b-dns.pcap'])
run([tool('editcap'),'-F','pcap','-r',a.output/'original-a.pcap',a.output/'a4-copy.pcap','4'])
run([tool('mergecap'),'-F','pcap','-w',a.output/'original-b.pcap',a.output/'b-dns.pcap',a.output/'a4-copy.pcap'])
run([tool('editcap'),'-F','pcap','-r',a.output/'original-a.pcap',a.output/'reference-displayed-a.pcap','4-5'])
run([tool('mergecap'),'-F','pcapng','-w',a.output/'merged-time.pcapng',a.output/'original-a.pcap',a.output/'original-b.pcap'])
(a.output/'build-execution.json').write_text(json.dumps({'synthetic':True,'commands':commands,'hashes':{x.name:hashlib.sha256(x.read_bytes()).hexdigest() for x in a.output.iterdir()}},indent=2))
