#!/usr/bin/env python3
"""Read-only independent check of raw DNS records, CSVs and author Calc import."""
from pathlib import Path
import struct,csv,hashlib,json,zipfile,xml.etree.ElementTree as E
ROOT=Path(__file__).resolve().parent
FIELDS=['frame.number','frame.time_epoch','ip.src','ip.dst','dns.qry.name','dns.a']
def parse_raw(path):
 b=path.read_bytes();assert b[:4]==b'\xd4\xc3\xb2\xa1';at=24;records=[]
 while at<len(b):
  sec,usec,cap,wire=struct.unpack_from('<IIII',b,at);at+=16;f=b[at:at+cap];at+=cap;assert len(f)==cap==wire and f[12:14]==b'\x08\x00';ip=f[14:];ihl=(ip[0]&15)*4;assert ip[9]==17;udp=ip[ihl:];dns=udp[8:];tx,flags,qd,an,ns,ar=struct.unpack_from('!6H',dns);assert qd==1 and ns==ar==0;pos=12;labels=[]
  while dns[pos]:n=dns[pos];pos+=1;labels.append(dns[pos:pos+n].decode());pos+=n
  pos+=5;answers=[]
  for _ in range(an):
   assert dns[pos:pos+2]==b'\xc0\x0c';typ,cl,ttl,ln=struct.unpack_from('!HHIH',dns,pos+2);assert (typ,cl,ln)==(1,1,4);pos+=12;answers.append('.'.join(map(str,dns[pos:pos+4])));pos+=4
  assert pos==len(dns);records.append(dict(epoch=f'{sec}.{usec:06d}000',src='.'.join(map(str,ip[12:16])),dst='.'.join(map(str,ip[16:20])),name='.'.join(labels),answers=answers))
 assert at==len(b);return records

def main():
 controls=json.loads((ROOT/'dns-baseline-controls.json').read_text());base=parse_raw(ROOT/'practice.pcap');rep=parse_raw(ROOT/'repeated-a.pcap');assert len(base)==6 and len(rep)==2;assert hashlib.sha256((ROOT/'practice.pcap').read_bytes()).hexdigest()==controls['baselineCaptureSha256'];assert (ROOT/'working-copy.pcap').read_bytes()==(ROOT/'practice.pcap').read_bytes();assert hashlib.sha256((ROOT/'repeated-a.pcap').read_bytes()).hexdigest()==controls['repeatedCaptureSha256']
 assert rep[1]['answers']==['198.51.100.10','198.51.100.20'];assert [i+1 for i,v in enumerate(base)if not v['answers']]==[1,3,5]
 for label,packets,occ in [('timeline',base,'a'),('repeated-all',rep,'a'),('repeated-first',rep,'f'),('repeated-last',rep,'l')]:
  with (ROOT/(label+'.csv')).open(newline='')as f:rows=list(csv.reader(f))
  assert rows[0]==FIELDS and len(rows)==len(packets)+1
  for i,(row,p)in enumerate(zip(rows[1:],packets),1):
   ans=p['answers'];value=';'.join(ans)if occ=='a'else (ans[0 if occ=='f'else -1]if ans else '')
   assert row==[str(i),p['epoch'],p['src'],p['dst'],p['name'],value]
 ns={'t':'urn:oasis:names:tc:opendocument:xmlns:table:1.0','o':'urn:oasis:names:tc:opendocument:xmlns:office:1.0','x':'urn:oasis:names:tc:opendocument:xmlns:text:1.0'}
 with zipfile.ZipFile(ROOT/'imported-repeated.ods')as z:assert z.testzip()is None;e=E.fromstring(z.read('content.xml'))
 observed=[]
 for row in e.findall('.//t:table-row',ns):
  cells=[]
  for c in row.findall('t:table-cell',ns):
   txt=''.join(c.itertext())
   if txt:assert c.get('{'+ns['o']+'}value-type')=='string'and c.get('{'+ns['t']+'}formula')is None;cells.append(txt)
  if cells:observed.append(cells)
 assert observed[0]==FIELDS and len(observed)==3 and observed[1]==['1',rep[0]['epoch'],rep[0]['src'],rep[0]['dst'],rep[0]['name']] and observed[2]==['2',rep[1]['epoch'],rep[1]['src'],rep[1]['dst'],rep[1]['name'],';'.join(rep[1]['answers'])]
 print(json.dumps(dict(rawBaselineFrames=len(base),rawRepeatedFrames=len(rep),exactCsvRows=True,allPopulatedOdsCellsText=True,noFormulas=True,scope='Local offline synthetic exercise verification; not learner execution, image or publication approval')))
if __name__=='__main__':main()
