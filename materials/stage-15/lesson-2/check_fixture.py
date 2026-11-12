"""Independent TShark row reconciliation, paired-message measurements and rebuild check."""
import argparse, csv, datetime, decimal, hashlib, json, pathlib, subprocess, tempfile

def check(inventory, events, pcap, rebuild=False):
    hosts = {r['host_id']: r for r in csv.DictReader(open(inventory), delimiter='\t')}
    rows = list(csv.DictReader(open(events), delimiter='\t'))
    available = subprocess.run(['tshark', '-G', 'fields'], capture_output=True, text=True, check=True).stdout
    optional = '\tdns.qry.name.len\t' in available
    fields = ['frame.number', 'frame.time_epoch', 'ip.src', 'ip.dst', 'udp.srcport', 'udp.dstport', 'dns.id', 'dns.flags.response', 'dns.qry.name', 'dns.qry.type', 'dns.flags.rcode', 'dns.count.answers', 'dns.a', 'dns.txt', 'dns.qry.name.len']
    if not optional:
        fields.remove('dns.qry.name.len')
    cmd = ['tshark', '-r', pcap, '-T', 'fields', '-E', 'separator=/t'] + sum([['-e', x] for x in fields], [])
    p = subprocess.run(cmd, capture_output=True, text=True, check=True)
    decoded = [dict(zip(fields, x.split('\t'))) for x in p.stdout.splitlines()]
    if not len(rows) == len(decoded) == 43:
        raise ValueError('Fixture validation failed')
    malformed = subprocess.run(['tshark', '-r', pcap, '-Y', '_ws.malformed', '-T', 'fields', '-e', 'frame.number'], capture_output=True, text=True, check=True)
    if not not malformed.stdout.strip():
        raise ValueError('Fixture validation failed')
    pairmap = {}
    pairs = []
    unmatched = {}
    summary = {}
    for r, d in zip(rows, decoded):
        if not int(d['frame.number']) == rows.index(r) + 1:
            raise ValueError('Fixture validation failed')
        expected = decimal.Decimal(str(datetime.datetime.fromisoformat(r['timestamp'].replace('Z', '+00:00')).timestamp()))
        if not decimal.Decimal(d['frame.time_epoch']) == expected:
            raise ValueError('Fixture validation failed')
        for a, b in [('src_ip', 'ip.src'), ('dst_ip', 'ip.dst'), ('src_port', 'udp.srcport'), ('dst_port', 'udp.dstport'), ('name', 'dns.qry.name')]:
            if not r[a] == d[b]:
                raise ValueError((r['event_id'], a))
        if not int(d['dns.id'], 0) == int(r['txid']):
            raise ValueError('Fixture validation failed')
        if not d['dns.flags.response'] == ('True' if r['qr'] == 'R' else 'False'):
            raise ValueError('Fixture validation failed')
        if not int(d['dns.qry.type']) == {'A': 1, 'AAAA': 28, 'TXT': 16}[r['qtype']]:
            raise ValueError('Fixture validation failed')
        if not int(d['dns.count.answers']) == int(r['answer_type'] != '-'):
            raise ValueError('Fixture validation failed')
        if r['qr'] == 'R':
            if not int(d['dns.flags.rcode']) == {'NOERROR': 0, 'NXDOMAIN': 3}[r['rcode']]:
                raise ValueError('Fixture validation failed')
        if r['answer_type'] == 'A':
            if not d['dns.a'] == r['answer_value']:
                raise ValueError('Fixture validation failed')
        if r['answer_type'] == 'TXT':
            if not d['dns.txt'] == r['answer_value']:
                raise ValueError('Fixture validation failed')
        h = hosts[r['host_id']]
        if not (r['group_id'] == h['group_id'] and r['name'].endswith('.' + h['group_suffix'])):
            raise ValueError('Fixture validation failed')
        t = datetime.datetime.fromisoformat(r['timestamp'].replace('Z', '+00:00'))
        if not datetime.datetime.fromisoformat(h['window_start_utc'].replace('Z', '+00:00')) <= t < datetime.datetime.fromisoformat(h['window_end_utc'].replace('Z', '+00:00')):
            raise ValueError('Fixture validation failed')
        if not (r['src_ip'], r['dst_ip']) == ((h['src_ip'], h['resolver_ip']) if r['qr'] == 'Q' else (h['resolver_ip'], h['src_ip'])):
            raise ValueError('Fixture validation failed')
        key = (r['host_id'], r['txid'], r['name'].lower(), r['qtype'], r['src_ip'] if r['qr'] == 'Q' else r['dst_ip'], r['dst_ip'] if r['qr'] == 'Q' else r['src_ip'], r['src_port'] if r['qr'] == 'Q' else r['dst_port'], r['dst_port'] if r['qr'] == 'Q' else r['src_port'])
        if r['qr'] == 'Q':
            pairmap[key] = (d['frame.number'], decimal.Decimal(d['frame.time_epoch']))
            unmatched[key] = d['frame.number']
        else:
            if not (key in unmatched and decimal.Decimal(d['frame.time_epoch']) > pairmap[key][1]):
                raise ValueError('Fixture validation failed')
            pairs.append({'queryFrame': unmatched.pop(key), 'responseFrame': d['frame.number'], 'event': r['event_id']})
        s = summary.setdefault(r['host_id'], {'group': h['group_id'], 'window': [h['window_start_utc'], h['window_end_utc']], 'labelMeasurements': [], 'answerTypes': {}, 'queries': 0, 'names': set(), 'types': {}, 'rcodes': {}, 'answers': 0, 'responses': 0})
        if r['qr'] == 'Q':
            lengths = [len(x.encode('ascii')) for x in r['name'].split('.')]
            s['labelMeasurements'].append({'frame': d['frame.number'], 'dottedNameLength': len(r['name']), 'longestLabelOctets': max(lengths), 'positionsFromLeft': [i + 1 for i, n in enumerate(lengths) if n == max(lengths)], 'reportedNameLength': d.get('dns.qry.name.len'), 'name': r['name']})
            s['queries'] += 1
            s['names'].add(r['name'].lower())
            s['types'][r['qtype']] = s['types'].get(r['qtype'], 0) + 1
        else:
            s['answerTypes'][r['answer_type']] = s['answerTypes'].get(r['answer_type'], 0) + 1
            s['responses'] += 1
            s['rcodes'][r['rcode']] = s['rcodes'].get(r['rcode'], 0) + 1
            s['answers'] += int(r['answer_type'] != '-')
    for s in summary.values():
        s['distinctNames'] = len(s.pop('names'))
    if rebuild:
        with tempfile.TemporaryDirectory() as td:
            subprocess.run(['python3', str(pathlib.Path(__file__).with_name('build_fixture.py')), '--inventory', inventory, '--events', events, '--out', td + '/rebuild.pcap'], capture_output=True, text=True, check=True)
            if not pathlib.Path(td + '/rebuild.pcap').read_bytes() == pathlib.Path(pcap).read_bytes():
                raise ValueError('Fixture validation failed')
    return {'optionalNameLengthAvailable': optional, 'state': 'PASS', 'captureSha256': hashlib.sha256(pathlib.Path(pcap).read_bytes()).hexdigest(), 'frames': len(decoded), 'exactRowsReconciled': len(rows), 'malformedFrames': [], 'summary': summary, 'pairs': pairs, 'unpairedQueryFrames': list(unmatched.values()), 'rebuildByteIdentical': rebuild, 'decoded': decoded, 'command': cmd, 'stderr': p.stderr}
if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--inventory', default='inventory.tsv')
    p.add_argument('--events', default='events.tsv')
    p.add_argument('--pcap', default='practice.pcap')
    p.add_argument('--rebuild-and-compare', action='store_true')
    a = p.parse_args()
    print(json.dumps(check(a.inventory, a.events, a.pcap, a.rebuild_and_compare), indent=2))
