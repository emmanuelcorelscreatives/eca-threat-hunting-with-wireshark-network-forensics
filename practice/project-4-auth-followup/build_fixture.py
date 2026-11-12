from pathlib import Path
import struct, socket, hashlib, json, csv, subprocess, sys, shutil
import argparse
parser=argparse.ArgumentParser(description='Build offline synthetic Project4 coursework without network access');parser.add_argument('--out-dir',required=True,type=Path);args=parser.parse_args();K=args.out_dir
if K.exists():raise SystemExit('Refusing existing output directory')
K.mkdir(parents=True)
def checksum(b):
 if len(b)%2:b+=b'\0'
 s=sum(struct.unpack('!%dH'%(len(b)//2),b));s=(s>>16)+(s&65535);s+=(s>>16);return (~s)&65535
def pkt(src,dst,sp,dp,seq,ack,flags,payload=b''):
 a=socket.inet_aton(src);b=socket.inet_aton(dst)
 tcp=struct.pack('!HHIIBBHHH',sp,dp,seq,ack,80,flags,64240,0,0)+payload
 c=checksum(a+b+struct.pack('!BBH',0,6,len(tcp))+tcp)
 tcp=tcp[:16]+struct.pack('!H',c)+tcp[18:]
 ip=struct.pack('!BBHHHBBH4s4s',69,0,20+len(tcp),1,0,64,6,0,a,b)
 ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
 return bytes.fromhex('0200000000020200000000010800')+ip+tcp
frames=[]
def add(sec,*args):frames.append((sec,pkt(*args)))
src='192.0.2.10'
for t,dst,port in [(0,'192.0.2.20',40000),(2,'192.0.2.21',40001)]:
 add(t,src,dst,port,445,1000,0,2);add(t+.1,dst,src,445,port,2000,1001,18);add(t+.2,src,dst,port,445,1001,2001,20)
add(4,src,'192.0.2.30',40002,445,1000,0,2)
# LDAPMessage messageID1 + BindRequest(version3, empty name, simple empty auth)
request=bytes.fromhex('300c020101600702010304008000')
def response(code):return bytes.fromhex('300c02010161070a01')+bytes([code])+bytes.fromhex('04000400')
for t,dst,port,code in [(10,'192.0.2.20',41000,0),(12,'192.0.2.21',41001,48)]:
 add(t,src,dst,port,389,3000,0,2);add(t+.1,dst,src,389,port,5000,3001,18);add(t+.2,src,dst,port,389,3001,5001,16)
 add(t+.3,src,dst,port,389,3001,5001,24,request);add(t+.4,dst,src,389,port,5001,3001+len(request),24,response(code))
 add(t+.5,src,dst,port,389,3001+len(request),5001+len(response(code)),17);add(t+.6,dst,src,389,port,5001+len(response(code)),3002+len(request),17);add(t+.7,src,dst,port,389,3002+len(request),5002+len(response(code)),16)
b=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
for t,p in frames:
 sec=1767225600+int(t);us=round((t-int(t))*1000000);b+=struct.pack('<IIII',sec,us,len(p),len(p))+p
capture=K/'practice.pcap'
if capture.exists():raise SystemExit('Refusing overwrite of existing fixture')
capture.write_bytes(b)
def csvout(name,cols,rows):
 with (K/name).open('w',newline='') as f:w=csv.writer(f);w.writerow(cols);w.writerows(rows)
csvout('discovery-map.csv',['source','attempted_target','responding_peer','frame_refs','observation'],[[src,'192.0.2.20','192.0.2.20','1;2;3','SYN;SYN-ACK;RST-ACK on TCP445'],[src,'192.0.2.21','192.0.2.21','4;5;6','SYN;SYN-ACK;RST-ACK on TCP445'],[src,'192.0.2.30','unknown','7','SYN only; no response in supplied capture']])
csvout('identity-events.csv',['record_id','original_time','time_zone','recording_computer','event_id','account','source_address','source_workstation','logon_type','status','substatus','destination_field','provenance'],[
 ['EV01','2026-01-01T00:00:10.500','UTC','DC-LAB',4771,'svc-lab',src,'','','0x18','','','FICTIONAL DESIGNED ROW'],
 ['EV02','2026-01-01T00:00:10.700','UTC','DC-LAB',4771,'svc-lab',src,'','','0x19','','','FICTIONAL DESIGNED ROW'],
 ['EV03','2026-01-01T00:00:11.000','UTC','DC-LAB',4776,'svc-lab','','LAB-CLIENT','','0xC000006A','','','FICTIONAL DESIGNED ROW'],
 ['EV04','2026-01-01T00:00:12.500','UTC','APP-B',4625,'svc-lab',src,'LAB-CLIENT','3','0xC000006D','0xC000006A','','FICTIONAL DESIGNED ROW'],
 ['EV05','2026-01-01T00:00:13.000','UTC','APP-A',4624,'svc-lab',src,'LAB-CLIENT','3','0x0','','','FICTIONAL DESIGNED ROW']])
csvout('address-map.csv',['address','fictional_system','role','mapping_basis'],[[src,'LAB-CLIENT','initiator','scenario assignment; not packet-derived identity'],['192.0.2.20','APP-A','peer A','scenario assignment'],['192.0.2.21','APP-B','peer B','scenario assignment'],['192.0.2.30','APP-C','attempted target','scenario assignment'],['192.0.2.40','DC-LAB','fictional KDC for separate protocol examples','scenario assignment']])
csvout('coverage.csv',['source_id','start_original','end_original','time_zone','clock_offset','coverage_limits'],[['PCAP','2026-01-01T00:00:00','2026-01-01T00:00:12.700','UTC','design-aligned; no measured clock evidence','practice.pcap;23 designed frames only; no production capture'],['DC-LAB','2026-01-01T00:00:10','2026-01-01T00:00:11.100','UTC','unknown in a real deployment','selected fictional excerpts only'],['APP-A','2026-01-01T00:00:13','2026-01-01T00:00:13','UTC','unknown in a real deployment','one supplied success event; incomplete host coverage'],['APP-B','2026-01-01T00:00:12.500','2026-01-01T00:00:12.500','UTC','unknown in a real deployment','one supplied failure event; incomplete host coverage'],['APP-C','unknown','unknown','unknown','unknown','no host records supplied'],['PROTOCOL_PCAP','2026-01-01T00:00:10.450','2026-01-01T00:00:12.620','UTC','design-aligned; no measured clock evidence','protocol-examples.pcap;14 offline protocol-shaped teaching frames only; no real authentication']])
csvout('case-evidence-inventory.csv',['source_id','availability','original_time_zone','coverage','clock_information','handling_restrictions'],[[x,'not supplied','unknown','unknown','unknown','restrict identity excerpts; preserve original'] for x in ['saved-case capture','saved-case identity events','saved-case target logs','saved-case discovery map','saved-case maintenance','saved-case address mapping']])
csvout('timeline-template.csv',['source_id','frame_or_event','original_time','original_zone','clock_uncertainty','observed_fact','proposed_relationship','confidence','unresolved_gap'],[])
csvout('asset-shortlist-template.csv',['system','attempted_target','responding_peer','corroborated_outcome','coverage','scope_classification','supporting_refs','unresolved_question'],[])
(K/'fixture-spec.json').write_text(json.dumps({'scope':'Academy-designed offline synthetic supplemental exercise; not the absent saved lesson case','epoch':1767225600,'packetCount':len(frames),'captureSha256':hashlib.sha256(b).hexdigest(),'network':'192.0.2.0/24 documentation range','ldap':'anonymous LDAPv3 binds, messageID1; APP-A result0 success, APP-B result48 inappropriateAuthentication; neither carries svc-lab credentials','identityRows':'manually designed fictional Windows-shaped CSV, not native EVTX or actual host authentication','timestamps':'designed shared UTC chronology; no measured production offsets','authoritativeSource':'build_fixture.py is the complete versioned source of all generated data; this JSON is an output summary, not a consumed specification'},indent=2))
csvout('discovery-map-template.csv',['source','attempted_target','responding_peer','frame_refs','observation'],[])
print(json.dumps({'capture':str(capture),'frames':len(frames),'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b)}))
