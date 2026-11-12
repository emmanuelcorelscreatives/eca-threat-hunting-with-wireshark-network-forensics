"""Independent TShark field validation plus exact offline regeneration."""
import argparse,csv,hashlib,json,pathlib,subprocess,tempfile,sys
if not __debug__: raise SystemExit('Optimization disables validation; refusing execution')

def run(root):
 fields=['eth.src','eth.dst','dns.id','dns.flags','dns.qry.type','dns.qry.class','dns.resp.name','dns.resp.type','dns.resp.class','dns.resp.ttl','udp.payload','frame.number','frame.time_epoch','arp.opcode','arp.src.hw_mac','arp.src.proto_ipv4','arp.dst.hw_mac','arp.dst.proto_ipv4','dhcp.id','dhcp.hw.mac_addr','dhcp.ip.client','dhcp.ip.your','dhcp.ip.relay','dhcp.option.dhcp','dhcp.option.dhcp_server_id','dhcp.option.requested_ip_address','dhcp.option.ip_address_lease_time','ip.src','ip.dst','udp.srcport','udp.dstport','dns.flags.response','dns.qry.name','dns.a','dns.qry.qu','ip.checksum.status','udp.checksum.status']
 result={'tsharkVersion':subprocess.check_output(['tshark','--version'],text=True).splitlines()[0],'captures':[]}
 plan=list(csv.DictReader((pathlib.Path(__file__).parent/'scenario-plan.csv').open()))
 from generate_fixture import M
 for stem,count in [('client-facing-synthetic',17),('relay-server-side-synthetic',2)]:
  path=root/(stem+'.pcap');cmd=['tshark','-r',str(path),'-o','ip.check_checksum:TRUE','-o','udp.check_checksum:TRUE','-T','fields','-E','separator=,','-E','quote=d']
  for f in fields:cmd+=['-e',f]
  decoded=subprocess.check_output(cmd,text=True,stderr=subprocess.PIPE);rows=list(csv.reader(decoded.splitlines()));assert len(rows)==count
  facts=[dict(zip(fields,r)) for r in rows]
  if count==17: clientfacts=facts
  expected=[x for x in plan if x['trace_id']==stem]
  for e,d in zip(expected,facts):
   f=dict(x.split('=',1) for x in e['fields'].split(';'))
   def eq(k,v): assert d[k].lower()==str(v).lower(),(e['event_id'],k,d[k],v)
   eq('eth.src',M.get(e['ether_src'],e['ether_src']));eq('eth.dst',M.get(e['ether_dst'],e['ether_dst']))
   if e['protocol']=='ARP':
    for k,v in [('arp.opcode',f['op']),('arp.src.hw_mac',M.get(f['sha'],f['sha'])),('arp.src.proto_ipv4',f['spa']),('arp.dst.hw_mac',M.get(f['tha'],f['tha'])),('arp.dst.proto_ipv4',f['tpa'])]:eq(k,v)
   else:
    for k in ['src','dst']:eq('ip.'+k,e['ip_'+k])
    for k,v in zip(['udp.srcport','udp.dstport'],f['udp'].split('>')):eq(k,v)
    eq('ip.checksum.status',1);eq('udp.checksum.status',1)
    if e['protocol']=='DHCP':
     for k,v in [('dhcp.id',f['xid']),('dhcp.hw.mac_addr',M.get(f['chaddr'],f['chaddr'])),('dhcp.ip.client',f['ci']),('dhcp.ip.your',f['yi']),('dhcp.ip.relay',f['gi']),('dhcp.option.dhcp',dict(DISCOVER=1,OFFER=2,REQUEST=3,ACK=5)[f['msg']])]:eq(k,v)
     for key,df in [('server','dhcp.option.dhcp_server_id'),('requested','dhcp.option.requested_ip_address'),('lease','dhcp.option.ip_address_lease_time')]:eq(df,f.get(key,''))
    elif e['protocol']=='mDNS':
     eq('dns.flags.response',True if f['qr']=='response' else False)
     eq('dns.id','0x0000')
     eq('dns.flags','0x8400' if f['qr']=='response' else '0x0000')
     if f['qr']=='query':
      eq('dns.qry.type',1);eq('dns.qry.class','0x0001');eq('dns.qry.qu',True)
     else:
      eq('dns.resp.name',f['name']);eq('dns.resp.type',1);eq('dns.resp.class','0x0001');eq('dns.resp.ttl',f['ttl'])
     eq('dns.a' if f['qr']=='response' else 'dns.qry.name',f['answer'] if f['qr']=='response' else f['name'])
    elif e['protocol']=='UDP':eq('udp.payload','000102')
   from datetime import datetime
   assert abs(float(d['frame.time_epoch'])-datetime.fromisoformat(e['time_utc'].replace('Z','+00:00')).timestamp())<0.000001
  pivots={}
  for filt in ['arp','dhcp','udp.port == 5353','_ws.malformed']:
   out=subprocess.check_output(['tshark','-r',str(path),'-Y',filt,'-T','fields','-e','frame.number'],text=True,stderr=subprocess.PIPE);pivots[filt]=[int(x) for x in out.split()]
  assert pivots==({'arp':[5,6,7,8,9,13,14,15],'dhcp':[1,2,3,4,16,17],'udp.port == 5353':[10,11,12],'_ws.malformed':[12]} if count==17 else {'arp':[],'dhcp':[1,2],'udp.port == 5353':[],'_ws.malformed':[]})
  (root/(stem+'-decoded.csv')).write_text(','.join(fields)+'\n'+decoded)
  result['captures'].append({'file':path.name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'frames':count,'pivots':pivots,'allPlannedFieldsAndTimestampsMatch':True,'ipAndUdpChecksumsValid':True})
 with tempfile.TemporaryDirectory() as t:
  subprocess.run([sys.executable,str(pathlib.Path(__file__).parent/'generate_fixture.py'),'--out-dir',t],check=True)
  for cap in result['captures']: assert (pathlib.Path(t)/cap['file']).read_bytes()==(root/cap['file']).read_bytes()
  refusal=subprocess.run([sys.executable,str(pathlib.Path(__file__).parent/'generate_fixture.py'),'--out-dir',t],capture_output=True,text=True);assert refusal.returncode and 'Refusing overwrite' in refusal.stderr
 result.update(exactRegeneration=True,overwriteRefused=True,networkPacketsSent=False)
 binding=list(csv.DictReader((root/'dhcp-binding-record.csv').open()))[0];
 ack=clientfacts[3]
 for key,field in [('client_mac','dhcp.hw.mac_addr'),('address','dhcp.ip.your'),('server_id','dhcp.option.dhcp_server_id'),('transaction_id','dhcp.id'),('lease_seconds','dhcp.option.ip_address_lease_time')]:assert binding[key]==ack[field]
 from datetime import datetime
 assert datetime.fromisoformat(binding['event_time_utc'].replace('Z','+00:00')).timestamp()==float(ack['frame.time_epoch'])
 (root/'actual-execution.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--input-dir',required=True);run(pathlib.Path(p.parse_args().input_dir))
