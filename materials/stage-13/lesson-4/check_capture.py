#!/usr/bin/env python3
"""Read-only raw PCAP checker for this exact Academy exercise. No network I/O."""
import pathlib,sys,struct,json,hashlib
r=pathlib.Path(sys.argv[1] if len(sys.argv)>1 else '.')
def records(path):
 b=path.read_bytes();assert b[:4]==b'\xd4\xc3\xb2\xa1','classic little-endian PCAP required';pos=24;out=[];prior=-1
 while pos<len(b):
  sec,usec,cap,orig=struct.unpack_from('<IIII',b,pos);pos+=16;assert cap<=orig and pos+cap<=len(b);packet=b[pos:pos+cap];pos+=cap;now=sec*1000000+usec;assert now>=prior;prior=now;out.append((now,cap,orig,packet))
 assert pos==len(b);return out
expected=json.loads((r/'capture-hashes.json').read_text());assert set(expected)=={'supplemental-session-patterns.pcap','supplemental-visibility-limits.pcap'},'exact two capture hashes required'
for name,digest in expected.items():assert hashlib.sha256((r/name).read_bytes()).hexdigest()==digest,'capture hash mismatch'
a=records(r/'supplemental-session-patterns.pcap');b=records(r/'supplemental-visibility-limits.pcap');assert len(a)==37 and len(b)==36
assert all(cap==orig for _,cap,orig,_ in a);assert [(i+1,x[1],x[2]) for i,x in enumerate(b) if x[1]<x[2]]==[(15,60,96)]
def canonical(x):
 packet=bytearray(x[3]);packet[18:20]=b'\0\0';packet[24:26]=b'\0\0';return x[0],x[1],x[2],bytes(packet)
expected_records=a[:5]+a[6:];assert len(expected_records)==len(b)
for i,(x,y) in enumerate(zip(expected_records,b)):
 if i==14:
  assert x[0]==y[0] and x[2]==y[2] and canonical(x)[3][:60]==canonical(y)[3]
 else:assert canonical(x)==canonical(y)
assert sum(x[3][23]==6 for x in a)==34 and sum(x[3][23]==17 for x in a)==3
requests=[i+1 for i,x in enumerate(a) if b'GET /practice/' in x[3]];assert requests==[4,14,24,28]
assert [int.from_bytes(a[i-1][3][34:36],'big') for i in requests]==[51001,51002,51003,51003]
print(json.dumps({'pass':True,'baselineFrames':len(a),'limitedFrames':len(b),'requestFrames':requests,'limitedTruncatedFrame':15,'omittedBaselineFrame':6}))
