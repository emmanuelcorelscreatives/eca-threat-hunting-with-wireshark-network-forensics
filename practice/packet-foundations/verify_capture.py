#!/usr/bin/env python3
"""Independently decode an authored offline fixture with installed TShark."""
import argparse
import datetime as dt
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from build_capture import generate

FIELDS = ['frame.number','frame.time_epoch','frame.protocols','frame.len','frame.cap_len',
          'ip.src','ip.dst','ip.checksum.status','udp.srcport','udp.dstport','udp.checksum.status',
          'tcp.srcport','tcp.dstport','tcp.seq_raw','tcp.ack_raw','tcp.len','tcp.flags','tcp.checksum.status',
          'dns.id','dns.flags.response','dns.qry.name','dns.a','icmp.type','icmp.ident','icmp.seq','icmp.checksum.status',
          'http.request.method','http.request.uri','http.response.code','tcp.analysis.flags']


def run(command):
    result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=60)
    return result.stdout


def verify(spec_path, capture_path):
    spec = json.loads(spec_path.read_text())
    body = capture_path.read_bytes()
    if generate(spec) != body:
        raise ValueError('Capture differs from deterministic regeneration')
    command = ['tshark','-r',str(capture_path),'-n','-o','ip.check_checksum:TRUE',
               '-o','udp.check_checksum:TRUE','-o','tcp.check_checksum:TRUE','-T','json']
    for field in FIELDS:
        command += ['-e',field]
    rows = json.loads(run(command))
    if len(rows) != len(spec['events']):
        raise ValueError('Decoded frame count differs from the authored specification')
    decoded=[]
    for number,(row,event) in enumerate(zip(rows,spec['events']),1):
        fields=row['_source']['layers']
        get=lambda key: fields.get(key,[''])[0]
        def require(key,value):
            if get(key) != str(value):
                raise ValueError(f'Frame {number}: {key} expected {value}, decoded {get(key)}')
        require('frame.number',number)
        require('ip.src',event['src']);require('ip.dst',event['dst'])
        require('ip.checksum.status',1)
        stamp=dt.datetime.fromisoformat(event['timestamp'].replace('Z','+00:00'))
        delta=stamp-dt.datetime(1970,1,1,tzinfo=dt.timezone.utc)
        expected=Decimal(delta.days*86400+delta.seconds)+Decimal(delta.microseconds)/1000000
        if Decimal(get('frame.time_epoch')) != expected:
            raise ValueError('Decoded UTC timestamp differs')
        if get('frame.len') != get('frame.cap_len'):
            raise ValueError('Unexpected truncated frame')
        if event['kind'] in ('udp','dns-query','dns-answer'):
            require('udp.srcport',event['sport']);require('udp.dstport',event['dport'])
            require('udp.checksum.status',1)
        if event['kind'].startswith('dns-'):
            require('dns.id',f"0x{event['transactionId']:04x}")
            require('dns.qry.name',event['name'])
            require('dns.flags.response','True' if event['kind']=='dns-answer' else 'False')
            if event['kind']=='dns-answer':require('dns.a',event['answer'])
        if event['kind']=='tcp':
            for key in ['sport','dport','seq','ack']:
                require({'sport':'tcp.srcport','dport':'tcp.dstport','seq':'tcp.seq_raw','ack':'tcp.ack_raw'}[key],event[key])
            require('tcp.checksum.status',1)
            if get('tcp.analysis.flags'):
                raise ValueError('Unexpected TCP analysis warning in the complete synthetic session')
        if event['kind'] in ('icmp-echo','icmp-reply'):
            require('icmp.type',8 if event['kind']=='icmp-echo' else 0)
            if int(get('icmp.ident'),0)!=event['identifier']:
                raise ValueError('Decoded ICMP identifier differs')
            require('icmp.seq',event['sequence']);require('icmp.checksum.status',1)
        decoded.append({key:value[0] if len(value)==1 else value for key,value in fields.items()})
    malformed=run(['tshark','-r',str(capture_path),'-n','-Y','_ws.malformed','-T','fields','-e','frame.number']).strip()
    if malformed:raise ValueError('Malformed packet found: '+malformed)
    exported=[]
    if spec['fixtureId']=='tcp-http-download':
        requests=[r for r in decoded if r.get('http.request.method')]
        responses=[r for r in decoded if r.get('http.response.code')]
        if len(requests)!=1 or requests[0]['http.request.method']!='GET' or requests[0]['http.request.uri']!='/sample/notes.txt':
            raise ValueError('Expected single decoded GET request')
        if len(responses)!=1 or responses[0]['http.response.code']!='200':
            raise ValueError('Expected single decoded200 response')
        with tempfile.TemporaryDirectory(prefix='eca-fixture-http-') as tmp:
            run(['tshark','-r',str(capture_path),'-n','-q','--export-objects','http,'+tmp])
            files=list(Path(tmp).iterdir())
            if len(files)!=1 or files[0].name!='notes.txt':raise ValueError('Unexpected exported HTTP object')
            data=files[0].read_bytes()
            expected=next(e['payloadText'].split('\r\n\r\n',1)[1].encode() for e in spec['events'] if e.get('payloadText','').startswith('HTTP/1.1 200'))
            if data!=expected:raise ValueError('HTTP object bytes differ from authored inert text')
            exported.append({'name':'notes.txt','bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
    return {'at':dt.datetime.now(dt.timezone.utc).isoformat(),'synthetic':True,
            'fixtureId':spec['fixtureId'],'captureSha256':hashlib.sha256(body).hexdigest(),
            'specSha256':hashlib.sha256(spec_path.read_bytes()).hexdigest(),'captureBytes':len(body),
            'verificationProgramSha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'generatorProgramSha256':hashlib.sha256(Path(__file__).with_name('build_capture.py').read_bytes()).hexdigest(),
            'toolVersion':run(['tshark','--version']).splitlines()[0],'decodedPackets':len(decoded),
            'deterministicRegenerationMatches':True,'allDecodedEndpointsAndTimestampsMatch':True,
            'allIPv4AndTransportChecksumsValid':True,'malformedPackets':0,
            'actualDecodedFields':decoded,'exportedInertHttpObjects':exported,
            'command':command,'scope':'Results describe this supplemental synthetic fixture only. No inference of real collection completeness, intent, person, execution or compromise.'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec',type=Path,required=True)
    parser.add_argument('--capture',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    report=verify(args.spec,args.capture)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x') as file:file.write(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ['actualDecodedFields','command']}))


if __name__=='__main__':
    main()
