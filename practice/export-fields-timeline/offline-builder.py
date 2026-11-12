#!/usr/bin/env python3
"""Build explicitly synthetic, deterministic PCAPs offline. Sends no packets.

JSON event specifications are data, never executable code. Checksums, TCP
sequence numbers and claimed application results remain independently verified
with TShark before a fixture or answer key is published.
"""
import argparse
import base64
import datetime as dt
import hashlib
import ipaddress
import json
from pathlib import Path
import struct

NETWORKS = tuple(ipaddress.ip_network(x) for x in
                 ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'))


def address(value):
    ip = ipaddress.IPv4Address(value)
    if not any(ip in network for network in NETWORKS):
        raise ValueError('Use a documentation-only IPv4 address')
    return ip.packed


def checksum(data):
    data += b'\0' if len(data) % 2 else b''
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def uint(value, maximum):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError('Out-of-range integer')
    return value


def payload(event):
    if 'payloadText' in event and 'payloadBase64' in event:
        raise ValueError('Choose one payload encoding')
    if 'payloadBase64' in event:
        return base64.b64decode(event['payloadBase64'], validate=True)
    return event.get('payloadText', '').encode('utf-8')


def dns_name(name):
    if not name.endswith(('.test', '.example')):
        raise ValueError('Use reserved synthetic DNS names')
    labels = [label.encode('ascii') for label in name.split('.')]
    if any(not 1 <= len(label) <= 63 for label in labels):
        raise ValueError('Invalid DNS label')
    return b''.join(bytes([len(label)]) + label for label in labels) + b'\0'


def transport(event, source, destination):
    kind = event['kind']
    if kind.startswith('dns-'):
        query = dns_name(event['name']) + struct.pack('!HH', 1, 1)
        txid = uint(event['transactionId'], 65535)
        if kind == 'dns-query':
            body = struct.pack('!HHHHHH', txid, 0x0100, 1, 0, 0, 0) + query
        elif kind == 'dns-answer':
            answers = event.get('answers', [event.get('answer')])
            if not 1 <= len(answers) <= 16:
                raise ValueError('Use one to sixteen A answers')
            body = struct.pack('!HHHHHH', txid, 0x8180, 1, len(answers), 0, 0) + query
            for answer in answers:
                body += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + address(answer)
        else:
            raise ValueError('Unknown DNS event')
    else:
        body = payload(event)
    if kind in ('udp', 'dns-query', 'dns-answer'):
        length = 8 + len(body)
        header = struct.pack('!HHHH', uint(event['sport'], 65535),
                             uint(event['dport'], 65535), length, 0)
        value = checksum(source + destination + struct.pack('!BBH', 0, 17, length) + header + body) or 65535
        return 17, header[:6] + struct.pack('!H', value) + body
    if kind == 'tcp':
        bits = {'F': 1, 'S': 2, 'R': 4, 'P': 8, 'A': 16, 'U': 32, 'E': 64, 'C': 128}
        flags = event['flags']
        if not flags or any(c not in bits for c in flags) or len(set(flags)) != len(flags):
            raise ValueError('Invalid TCP flags')
        header = struct.pack('!HHIIBBHHH', uint(event['sport'], 65535), uint(event['dport'], 65535),
                             uint(event['seq'], 0xffffffff), uint(event['ack'], 0xffffffff),
                             0x50, sum(bits[c] for c in flags), 65535, 0, 0)
        value = checksum(source + destination + struct.pack('!BBH', 0, 6, len(header) + len(body)) + header + body)
        return 6, header[:16] + struct.pack('!H', value) + header[18:] + body
    if kind in ('icmp-echo', 'icmp-reply'):
        header = struct.pack('!BBHHH', 8 if kind == 'icmp-echo' else 0, 0, 0,
                             uint(event['identifier'], 65535), uint(event['sequence'], 65535))
        return 1, header[:2] + struct.pack('!H', checksum(header + body)) + header[4:] + body
    raise ValueError('Unsupported event kind: ' + kind)


def frame(event, ident):
    source, destination = address(event['src']), address(event['dst'])
    protocol, body = transport(event, source, destination)
    if len(body) > 65515:
        raise ValueError('IPv4 datagram too large')
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body), ident, 0, 64, protocol, 0, source, destination)
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    mac = lambda ip: b'\x02\x00' + ip
    return mac(destination) + mac(source) + b'\x08\x00' + header + body


def generate(spec):
    if spec.get('version') != 1 or spec.get('synthetic') is not True:
        raise ValueError('An explicit synthetic version1 specification is required')
    events = spec['events']
    if not 1 <= len(events) <= 60000:
        raise ValueError('Invalid event count')
    result = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    previous = -1
    for index, event in enumerate(events, 1):
        time = dt.datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
        if time.tzinfo is None:
            raise ValueError('Timestamp requires an explicit time zone')
        delta = time.astimezone(dt.timezone.utc) - dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
        micros = delta.days * 86400_000000 + delta.seconds * 1000000 + delta.microseconds
        if micros < previous or micros < 0:
            raise ValueError('Events must be in timestamp order')
        previous = micros
        packet = frame(event, index)
        if len(packet) > 65535:
            raise ValueError('Frame exceeds capture snaplen')
        captured = event.get('capturedBytes', len(packet))
        if type(captured) is not int or not 14 <= captured <= len(packet):
            raise ValueError('Invalid intentional truncation')
        seconds, fraction = divmod(micros, 1000000)
        result.extend(struct.pack('<IIII', seconds, fraction, captured, len(packet)))
        result.extend(packet[:captured])
    return bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    data = generate(json.loads(args.spec.read_text()))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('xb') as output:
        output.write(data)
    print(json.dumps({'synthetic': True, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}))


if __name__ == '__main__':
    main()
