#!/usr/bin/env python3
"""Offline fixed-fixture checker. No sockets, capture, shell execution or OS service actions."""
import argparse,pathlib,hashlib,json,subprocess,csv,struct,sys

def classic(data):
 assert data[:4]==b'\xd4\xc3\xb2\xa1','Unsupported original PCAP';o=24;packets=[]
 while o<len(data):
  sec,usec,n,wire=struct.unpack_from('<IIII',data,o);o+=16;assert n==wire and o+n<=len(data),'Truncated original';packets.append((sec*1000000+usec,data[o:o+n]));o+=n
 assert o==len(data);return packets

def nextgen(data):
 assert data[:4]==b'\x0a\x0d\x0d\x0a','Not PCAPNG';o=0;packets=[]
 while o<len(data):
  t,n=struct.unpack_from('<II',data,o);assert n>=12 and n%4==0 and o+n<=len(data) and struct.unpack_from('<I',data,o+n-4)[0]==n,'Bad PCAPNG block'
  if t==6:
   iid,hi,lo,cap,wire=struct.unpack_from('<IIIII',data,o+8);assert iid==0 and cap==wire;packets.append(((hi<<32)|lo,data[o+28:o+28+cap]))
  o+=n
 assert o==len(data);return packets

def main():
 a=argparse.ArgumentParser();a.add_argument('--tshark',default='tshark');a.add_argument('--directory',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parent);args=a.parse_args();k=args.directory
 expected=json.loads((k/'expected-results.json').read_text());original=(k/'practice.pcap').read_bytes();converted=(k/'rpc-service-synthetic.pcapng').read_bytes()
 assert hashlib.sha256(original).hexdigest()==expected['pcapSha256'],'Original hash mismatch'
 assert hashlib.sha256(converted).hexdigest()==expected['pcapngSha256'],'Converted hash mismatch'
 packets=classic(original);assert packets==nextgen(converted),'Conversion changed packet bytes/timestamps/order';assert len(packets)==46
 def run(extra):
  p=subprocess.run([args.tshark,'-n','-r',str(k/'rpc-service-synthetic.pcapng'),'-d','tcp.port==17454,nbss']+extra,capture_output=True,text=True,check=True);return p.stdout
 version=subprocess.run([args.tshark,'--version'],capture_output=True,text=True,check=True).stdout;assert '4.4.0' in version.splitlines()[0],'Recorded fixture checker requires TShark4.4.0'
 fields=list(expected['rows'][0]);options=['-T','fields','-E','header=y','-E','separator=,','-E','quote=d']
 for f in fields:options+=['-e',f]
 rows=list(csv.DictReader(run(options).splitlines()));assert rows==expected['rows'],'Decoded fields differ from recorded fixed fixture'
 def frames(f):return [int(x)for x in run(['-Y',f,'-T','fields','-e','frame.number']).split()]
 assert frames('dcerpc')==[28,31,32,35,36,39,40,43,44]
 assert len(frames('smb2 or dcerpc'))==40
 assert frames('_ws.malformed')==[],'Malformed dissection'
 assert frames('dcerpc.opnum == 19')==[44],'Start reply must remain absent'
 assert frames('dcerpc.opnum == 15')==[32,35]
 assert frames('dcerpc.opnum == 16')==[36,39]
 assert frames('dcerpc.opnum == 6')==[40,43]
 rpc=run(['-Y','dcerpc','-V'])
 for required in ['367abb81-9844-35f1-ad32-98f038001003','SVCCTL V2.0','Acceptance (0)','AcademyExampleSvc','State: SVCCTL_STOPPED (1)','WERR_OK','000000004d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d','0000000053535353535353535353535353535353']:
  assert required in rpc,'Missing interface/handle/status evidence: '+required
 for n in [28,31,32,35,36,39,40,43,44]:
  row=rows[n-1];assert row['smb2.sesid']==expected['sessionId'] and row['smb2.tid']==expected['IPCtreeId'],'SMB linkage differs'
 for n in [28,30,32,34,36,38,40,42,44]:assert rows[n-1]['smb2.fid']==expected['pipeFileId'],'Pipe handle in request differs'
 assert rows[11]['_ws.col.info'].endswith('\\DATA') and rows[23]['_ws.col.info'].endswith('\\IPC$')
 assert rows[25]['smb2.filename']=='svcctl'
 for n in [32,36,40,44]:assert rows[n-1]['tcp.srcport']==expected['clientPort'] and rows[n-1]['tcp.dstport']=='17454'
 for n in [31,35,39,43]:assert rows[n-1]['tcp.srcport']=='17454'
 checks=run(['-o','ip.check_checksum:TRUE','-o','tcp.check_checksum:TRUE','-T','fields','-E','header=y','-E','separator=,','-e','ip.checksum.status','-e','tcp.checksum.status'])
 checksum_rows=list(csv.DictReader(checks.splitlines()));checksum_counts={}
 for field in ['ip.checksum.status','tcp.checksum.status']:
  counts={name:sum(row[field]==value for row in checksum_rows)for name,value in {'bad':'0','good':'1','unverified':'2','not_present':'3','illegal':'4','partial':'5','unavailable':''}.items()};assert sum(counts.values())==46 and counts['good']==46,'Changed checksum outcome: '+field+str(counts);checksum_counts[field]=counts
 host=list(csv.DictReader((k/'host-event-comparison-synthetic.csv').open()))
 expected_host=[{'provenance': 'AUTHORED_HYPOTHETICAL', 'event_ref': 'H01', 'original_event_record_id': 'SIM-1001', 'computer': 'LAB-TARGET', 'channel': 'Security', 'provider': 'Microsoft-Windows-Security-Auditing', 'event_id': '4697', 'time_created_utc': '2025-02-06T09:00:00.650Z', 'service_name': 'AcademyExampleSvc', 'image_path': 'C:\\Academy\\example-service.exe', 'process_id': '', 'parent_image': '', 'clock_context': 'Hypothetical host clock; offset unknown, not linked to real capture'}, {'provenance': 'AUTHORED_HYPOTHETICAL', 'event_ref': 'H02', 'original_event_record_id': 'SIM-1002', 'computer': 'LAB-TARGET', 'channel': 'Security', 'provider': 'Microsoft-Windows-Security-Auditing', 'event_id': '4688', 'time_created_utc': '2025-02-06T09:00:00.720Z', 'service_name': '', 'image_path': 'C:\\Windows\\System32\\notepad.exe', 'process_id': '0x0700', 'parent_image': 'C:\\Windows\\explorer.exe', 'clock_context': 'Hypothetical host clock; offset unknown, not linked to real capture'}]
 assert host==expected_host,'Complete hypothetical host schema/value/time/process/clock comparison changed'
 assert len(host)==2 and all(h['provenance']=='AUTHORED_HYPOTHETICAL' and h['computer']=='LAB-TARGET' and 'offset unknown' in h['clock_context']for h in host)
 assert [h['event_id']for h in host]==['4697','4688'] and host[0]['service_name']=='AcademyExampleSvc' and host[0]['image_path']!=host[1]['image_path'],'Hypothetical comparison changed'
 assert [h['original_event_record_id']for h in host]==['SIM-1001','SIM-1002'],'Never promote synthetic references to actual records'
 print(json.dumps({'verdict':'pass','scope':'Fixed offline inert Academy lab; NOT Windows execution, real audit export or OS-service proof','packets':len(packets),'conversionPacketBytesAndTimestampsEqual':True,'smbOrRpc':40,'rpcFrames':[28,31,32,35,36,39,40,43,44],'missingStartReply':True,'checksumCounts':checksum_counts,'hostRows':'2 authored hypothetical, no actual audit corroboration','pcapSha256':hashlib.sha256(original).hexdigest(),'pcapngSha256':hashlib.sha256(converted).hexdigest(),'version':version.splitlines()[0]},indent=2))
if __name__=='__main__':
 try:main()
 except Exception as e:print(json.dumps({'verdict':'fail','error':str(e)}));sys.exit(1)
