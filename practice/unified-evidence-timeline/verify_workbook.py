#!/usr/bin/env python3
"""Validate the blank Academy workbook without modifying the supplied original."""
from pathlib import Path
import hashlib,json,subprocess,tempfile,xml.etree.ElementTree as E,zipfile
ROOT=Path(__file__).resolve().parent
NS={p:'urn:oasis:names:tc:opendocument:xmlns:'+n+':1.0' for p,n in [('table','table'),('style','style'),('number','datastyle')]}
def q(p,n):return '{'+NS[p]+'}'+n
def inspect(file,schema):
 with zipfile.ZipFile(file) as z:
  assert z.testzip() is None,'ZIP integrity failed'
  doc=E.fromstring(z.read('content.xml'))
 sheets=doc.findall('.//'+q('table','table'));assert [t.get(q('table','name')) for t in sheets]==list(schema),'Sheet names changed'
 styles={s.get(q('style','name')):s for s in doc.findall('.//'+q('style','style'))};text_styles={s.get(q('style','name')) for s in doc.findall('.//'+q('number','text-style'))}
 for t,headers in zip(sheets,schema.values()):
  rows=t.findall(q('table','table-row'));actual=[''.join(c.itertext()) for c in rows[0].findall(q('table','table-cell'))];assert actual[:len(headers)]==headers and not any(actual[len(headers):]),'Header mismatch'
  assert all(not ''.join(c.itertext()).strip() for row in rows[1:] for c in row.findall(q('table','table-cell'))),'Unexpected case data'
  seen=0
  for col in t.findall(q('table','table-column')):
   if seen>=len(headers):break
   style=styles[col.get(q('table','default-cell-style-name'))];assert style.get(q('style','data-style-name')) in text_styles,'Column does not preserve text'
   seen+=int(col.get(q('table','number-columns-repeated'),'1'))
  assert seen>=len(headers),'Missing column formats'
 return {name:len(headers) for name,headers in schema.items()}
def main():
 file=ROOT/'unified-evidence-timeline.ods';schema=json.loads((ROOT/'schema.json').read_text());before=file.read_bytes();sheets=inspect(file,schema)
 with tempfile.TemporaryDirectory(prefix='academy-timeline-check-') as d:
  temp=Path(d);destination=temp/'converted';destination.mkdir();cmd=['libreoffice','-env:UserInstallation='+(temp/'profile').as_uri(),'--headless','--convert-to','ods','--outdir',str(destination),str(file)];result=subprocess.run(cmd,capture_output=True,text=True,timeout=60);assert result.returncode==0,(result.stdout,result.stderr);roundtrip=destination/file.name;assert roundtrip.is_file(),(result.stdout,result.stderr);inspect(roundtrip,schema)
 assert file.read_bytes()==before,'Original workbook changed'
 print(json.dumps({'sheets':sheets,'dataRows':0,'textFormatsVerified':True,'actualCalcRoundtripPassed':True,'originalPreserved':True,'sha256':hashlib.sha256(before).hexdigest(),'officeVersion':subprocess.check_output(['libreoffice','--version'],text=True).strip()}))
if __name__=='__main__':main()
