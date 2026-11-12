import pathlib,json,struct,sys
r=pathlib.Path(__file__).parent;out=pathlib.Path(sys.argv[1]);out.mkdir(exist_ok=False)
rows=json.loads((r/'packet-records.json').read_text())
for part,name in [('baseline','synthetic-authorized-baseline.pcap'),('cases','synthetic-labelled-cases.pcap')]:
 b=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
 for x in rows:
  if (x['partition']=='baseline')!=(part=='baseline'):continue
  p=bytes.fromhex(x['hex']);b+=struct.pack('<IIII',x['seconds'],x['microseconds'],len(p),len(p))+p
 (out/name).write_bytes(b)
