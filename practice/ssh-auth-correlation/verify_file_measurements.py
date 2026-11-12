"""Read-only classic-PCAP accounting for the recorded Wireshark4.4 UI counter."""
from pathlib import Path
import argparse,hashlib,json,struct
p=argparse.ArgumentParser(description=__doc__);p.add_argument('capture',type=Path);a=p.parse_args();b=a.capture.read_bytes()
if b[:4]!=bytes.fromhex('d4c3b2a1') or len(b)<24:raise ValueError('Expected the supplied little-endian microsecond classic PCAP')
rows=[];offset=24
while offset<len(b):
 if len(b)-offset<16:raise ValueError('Incomplete record header')
 seconds,microseconds,captured,original=struct.unpack_from('<IIII',b,offset)
 if microseconds>=1000000 or captured>original or offset+16+captured>len(b):raise ValueError('Invalid or truncated packet record')
 rows.append({'record':len(rows)+1,'recordHeaderOffset':offset,'payloadOffset':offset+16,'capturedLength':captured,'recordEnd':offset+16+captured});offset+=16+captured
if not rows:raise ValueError('This exercise requires its nonempty supplied capture')
last=rows[-1];accounted=24+len(rows)*16+sum(r['capturedLength']for r in rows);assert accounted==len(b)
print(json.dumps({'captureSha256':hashlib.sha256(b).hexdigest(),'recordCount':len(rows),'globalHeaderBytes':24,'recordHeaderBytes':16,'capturedPacketBytes':sum(r['capturedLength']for r in rows),'filesystemLengthBytes':len(b),'accountedFullFileBytes':accounted,'lastRecord':last,'recordedBuildGuiCounterFormula':'last recordHeaderOffset + capturedLength','recordedBuildGuiCounterBytes':last['recordHeaderOffset']+last['capturedLength'],'differenceBytes':len(b)-(last['recordHeaderOffset']+last['capturedLength']),'readOnly':True,'networkUsed':False},indent=2))
