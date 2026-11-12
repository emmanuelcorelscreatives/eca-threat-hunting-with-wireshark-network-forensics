#!/usr/bin/env python3
"""Read-only independent TShark selection checks. No network capture or writes to inputs."""
import argparse, hashlib, json, subprocess
from pathlib import Path
FILTERS={'ip.src == 192.0.2.10':[1,3], 'ip.addr == 192.0.2.10':[1,2,3,4], 'tcp && ip.addr == 192.0.2.10':[1,2], 'ip.src!= 192.0.2.10':[2,4,5,6], 'not (ip.src == 192.0.2.10)':[2,4,5,6,7]}
def main():
 p=argparse.ArgumentParser(); p.add_argument('--tshark',default='tshark'); p.add_argument('--capture',default='practice.pcap',type=Path); a=p.parse_args()
 def run(*args):
  r=subprocess.run([a.tshark,'-n','-r',str(a.capture),*args],capture_output=True,text=True,check=True)
  return r.stdout
 rows=run('-T','fields','-E','separator=,','-e','frame.number','-e','eth.type','-e','ip.src','-e','ip.dst','-e','tcp.seq_raw','-e','tcp.ack_raw','-e','arp.src.proto_ipv4','-e','arp.dst.proto_ipv4').strip().splitlines()
 assert len(rows)==7,rows
 expected=[['1','0x0800','192.0.2.10','192.0.2.20','1000','0','',''],['2','0x0800','192.0.2.20','192.0.2.10','9000','1001','',''],['3','0x0800','192.0.2.10','192.0.2.53','','','',''],['4','0x0800','192.0.2.53','192.0.2.10','','','',''],['5','0x0800','192.0.2.30','192.0.2.40','3000','0','',''],['6','0x0800','192.0.2.30','192.0.2.40','','','',''],['7','0x0806','','','','','192.0.2.30','192.0.2.40']]
 assert [r.split(',') for r in rows]==expected,rows
 assert not run('-Y','_ws.malformed','-T','fields','-e','frame.number').strip()
 results={}
 for expr,want in FILTERS.items():
  got=[int(x) for x in run('-Y',expr,'-T','fields','-e','frame.number').split()]
  assert got==want,(expr,got,want)
  results[expr]=got
 print(json.dumps({'verdict':'pass','captureSha256':hashlib.sha256(a.capture.read_bytes()).hexdigest(),'frameCount':7,'decodedRows':rows,'filters':results,'limits':'Synthetic offline controls only; no collection coverage or legitimacy finding.'},indent=2))
if __name__=='__main__': main()
