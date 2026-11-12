#!/usr/bin/env python3
"""Offline exact-byte replay of an Academy synthetic TLS fixture. No network access."""
import pathlib,json,hashlib,struct,sys
RECORD_SHA='f5ff46ff38ac91facdc667f861034c74013c9155de89cb02ee5adcb53bb411be'
def build(source,output):
 raw=pathlib.Path(source).read_bytes()
 if hashlib.sha256(raw).hexdigest()!=RECORD_SHA:raise ValueError('Input hash mismatch; refusing altered packet records')
 data=json.loads(raw);packets=data['records'];assert len(packets)==76
 def block(kind,body):
  size=12+len(body);return struct.pack('<II',kind,size)+body+struct.pack('<I',size)
 capture=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))+block(1,struct.pack('<HHI',1,0,65535))
 last=0
 for row in packets:
  ts=row['timestamp_us'];frame=bytes.fromhex(row['hex'])
  if ts<last or not 54<=len(frame)<=65535:raise ValueError('Invalid timestamp or frame')
  last=ts;pad=b'\0'*((-len(frame))%4)
  capture+=block(6,struct.pack('<IIIII',0,ts>>32,ts&0xffffffff,len(frame),len(frame))+frame+pad)
 with pathlib.Path(output).open('xb') as f:f.write(capture)
 return {'file':str(output),'frames':len(packets),'bytes':len(capture),'sha256':hashlib.sha256(capture).hexdigest()}
if __name__=='__main__':
 if len(sys.argv)>3:raise SystemExit('Usage: python rebuild_capture.py [output.pcapng] [packet-records.json]')
 here=pathlib.Path(__file__).resolve().parent
 print(json.dumps(build(sys.argv[2] if len(sys.argv)>2 else here/'packet-records.json',sys.argv[1] if len(sys.argv)>1 else here/'hidden-flows.pcapng'),indent=2))
