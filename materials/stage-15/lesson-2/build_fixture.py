"""Offline deterministic DNS fixture builder; no network sockets or third party modules."""
import argparse, csv, datetime, ipaddress, pathlib, struct

def checksum(b):
    b += b'\x00' * (len(b) % 2)
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s & 65535) + (s >> 16)
    s = (s & 65535) + (s >> 16)
    return ~s & 65535

def namewire(name):
    if not (name.endswith('.test') and name.isascii()):
        raise ValueError('Fixture validation failed')
    labels = name.split('.')
    if not all((0 < len(x) <= 63 for x in labels)):
        raise ValueError('Fixture validation failed')
    b = b''.join((bytes([len(x)]) + x.encode() for x in labels)) + b'\x00'
    if not len(b) <= 255:
        raise ValueError('Fixture validation failed')
    return b

def build(inv, events, out):
    dest = pathlib.Path(out)
    if dest.exists():
        raise FileExistsError('Refuse to replace existing output')
    inventory = list(csv.DictReader(open(inv), delimiter='\t'))
    hosts = {r['host_id']: r for r in inventory}
    if not len(hosts) == len(inventory) == 3:
        raise ValueError('Fixture validation failed')
    if not set(hosts) == {'C', 'T', 'D'}:
        raise ValueError('Fixture validation failed')
    if not len({(r['window_start_utc'], r['window_end_utc'], r['observation_point'], r['role'], r['resolver_ip']) for r in inventory}) == 1:
        raise ValueError('Fixture validation failed')
    if not len({r['src_ip'] for r in inventory}) == 3:
        raise ValueError('Fixture validation failed')
    pending = {}
    rows = list(csv.DictReader(open(events), delimiter='\t'))
    data = bytearray(struct.pack('<IHHIIII', 2712847316, 2, 4, 0, 0, 65535, 1))
    last = None
    ids = set()
    for index, r in enumerate(rows, 1):
        if not r['event_id'] not in ids:
            raise ValueError('Fixture validation failed')
        ids.add(r['event_id'])
        h = hosts[r['host_id']]
        if not (r['group_id'] == h['group_id'] and r['name'].endswith('.' + h['group_suffix'])):
            raise ValueError('Fixture validation failed')
        t = datetime.datetime.fromisoformat(r['timestamp'].replace('Z', '+00:00'))
        if not datetime.datetime.fromisoformat(h['window_start_utc'].replace('Z', '+00:00')) <= t < datetime.datetime.fromisoformat(h['window_end_utc'].replace('Z', '+00:00')):
            raise ValueError('Fixture validation failed')
        if not (last is None or t >= last):
            raise ValueError('Fixture validation failed')
        last = t
        key = (r['host_id'], r['txid'], r['name'].lower(), r['qtype'])
        response = r['qr'] == 'R'
        if not r['qr'] in ['Q', 'R']:
            raise ValueError('Fixture validation failed')
        if not (r['src_ip'], r['dst_ip']) == ((h['resolver_ip'], h['src_ip']) if response else (h['src_ip'], h['resolver_ip'])):
            raise ValueError('Fixture validation failed')
        if response:
            if not key in pending:
                raise ValueError('Fixture validation failed')
            q = pending.pop(key)
            if not (t > q[0] and r['src_port'] == q[2] and (r['dst_port'] == q[1])):
                raise ValueError('Fixture validation failed')
        else:
            if not key not in pending:
                raise ValueError('Fixture validation failed')
            pending[key] = (t, r['src_port'], r['dst_port'])
        for ip in [r['src_ip'], r['dst_ip']]:
            if not ipaddress.ip_address(ip) in ipaddress.ip_network('192.0.2.0/24'):
                raise ValueError('Fixture validation failed')
        typ = {'A': 1, 'AAAA': 28, 'TXT': 16}[r['qtype']]
        an = b''
        if r['answer_type'] != '-':
            if not (response and r['rcode'] == 'NOERROR' and (r['answer_type'] == r['qtype'])):
                raise ValueError('Fixture validation failed')
            if r['answer_type'] == 'A':
                if not ipaddress.ip_address(r['answer_value']) in ipaddress.ip_network('198.51.100.0/24'):
                    raise ValueError('Fixture validation failed')
                payload = ipaddress.ip_address(r['answer_value']).packed
            elif r['answer_type'] == 'TXT':
                payload = r['answer_value'].encode('ascii')
                if not len(payload) <= 255:
                    raise ValueError('Fixture validation failed')
                payload = bytes([len(payload)]) + payload
            else:
                raise ValueError('Unsupported answer')
            an = b'\xc0\x0c' + struct.pack('!HHIH', typ, 1, 60, len(payload)) + payload
        rc = {'NOERROR': 0, 'NXDOMAIN': 3}[r['rcode']] if response else 0
        if not response:
            if not r['rcode'] == r['answer_type'] == r['answer_value'] == '-':
                raise ValueError('Fixture validation failed')
        if rc:
            if not not an:
                raise ValueError('Fixture validation failed')
        dns = struct.pack('!HHHHHH', int(r['txid']), 33152 | rc if response else 256, 1, int(bool(an)), 0, 0) + namewire(r['name']) + struct.pack('!HH', typ, 1)
        dns += an
        src = ipaddress.ip_address(r['src_ip']).packed
        dst = ipaddress.ip_address(r['dst_ip']).packed
        sport, dport = (int(r['src_port']), int(r['dst_port']))
        if not (sport == 53 if response else dport == 53):
            raise ValueError('Fixture validation failed')
        udp = struct.pack('!HHHH', sport, dport, len(dns) + 8, 0) + dns
        cs = checksum(src + dst + struct.pack('!BBH', 0, 17, len(udp)) + udp) or 65535
        udp = udp[:6] + struct.pack('!H', cs) + udp[8:]
        ip = struct.pack('!BBHHHBBH4s4s', 69, 0, 20 + len(udp), index, 0, 64, 17, 0, src, dst)
        ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
        pkt = bytes.fromhex('0200000000530200000000100800') + ip + udp
        sec = int(t.timestamp())
        usec = t.microsecond
        data += struct.pack('<IIII', sec, usec, len(pkt), len(pkt)) + pkt
    with dest.open('xb') as f:
        f.write(data)
    return len(rows)
if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--inventory', default='inventory.tsv')
    p.add_argument('--events', default='events.tsv')
    p.add_argument('--out', required=True)
    a = p.parse_args()
    print(build(a.inventory, a.events, a.out))
