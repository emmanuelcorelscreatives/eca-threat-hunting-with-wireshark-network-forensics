#!/usr/bin/env python3
"""Build a deterministic, synthetic offline DNS practice capture. Sends no traffic."""
import hashlib, json, socket, struct
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def checksum(data):
    if len(data) % 2: data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16: total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

def packet(src, dst, sport, dport, payload, ident):
    a, b = socket.inet_aton(src), socket.inet_aton(dst)
    length = 8 + len(payload)
    udp0 = struct.pack('!HHHH', sport, dport, length, 0)
    udpcheck = checksum(a+b+struct.pack('!BBH', 0, 17, length)+udp0+payload) or 0xffff
    udp = struct.pack('!HHHH', sport, dport, length, udpcheck)+payload
    ip0 = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(udp), ident, 0, 64, 17, 0, a, b)
    ip = ip0[:10]+struct.pack('!H', checksum(ip0))+ip0[12:]
    # Locally administered synthetic MAC addresses; no real host data.
    mac_client, mac_dns = bytes.fromhex('020000000010'), bytes.fromhex('020000000053')
    eth = (mac_dns+mac_client if sport != 53 else mac_client+mac_dns)+b'\x08\x00'
    return eth+ip+udp

def main():
    out=ROOT/'captures';out.mkdir(parents=True,exist_ok=True)
    records=[];expected=[]
    for i, name in enumerate(['portal.academy.test','updates.academy.test','portal.academy.test']):
        qname=b''.join(bytes([len(x)])+x.encode('ascii') for x in name.split('.'))+b'\0'
        question=qname+struct.pack('!HH',1,1)
        txid=0x1001+i;port=53000+i
        query=struct.pack('!HHHHHH',txid,0x0100,1,0,0,0)+question
        reply=struct.pack('!HHHHHH',txid,0x8180,1,1,0,0)+question+b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+socket.inet_aton('198.51.100.20')
        records.append((1794355200+i*30,0,packet('192.0.2.10','192.0.2.53',port,53,query,2*i+1)))
        records.append((1794355200+i*30,20000,packet('192.0.2.53','192.0.2.10',53,port,reply,2*i+2)))
        expected.append({'query_frame':2*i+1,'response_frame':2*i+2,'transaction_id':txid,'query_name':name,'answer':'198.51.100.20','latency_seconds':0.02})
    path=out/'synthetic-dns-baseline.pcap'
    with path.open('wb') as f:
        f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
        for seconds,micros,data in records:f.write(struct.pack('<IIII',seconds,micros,len(data),len(data))+data)
    manifest={'synthetic':True,'scope':'Offline teaching fixture. Not observed production traffic or evidence of compromise. This supplemental practice file does not replace any saved demonstration that explicitly has no case file.','generator':'tools/generate_baseline.py','capture':str(path.relative_to(ROOT)),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'packets':6,'timestamps':'UTC; fixed synthetic timestamps','client':'192.0.2.10','dns_server':'192.0.2.53','transactions':expected}
    (ROOT/'baseline-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(manifest))
if __name__=='__main__':main()
