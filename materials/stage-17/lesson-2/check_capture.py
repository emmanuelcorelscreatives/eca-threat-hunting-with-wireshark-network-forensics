"""Fail closed on published fixture identity and required decoded SMB relationships."""
import pathlib, subprocess, json, hashlib, csv, io, sys
def require(ok, message):
    if not ok:
        raise RuntimeError(message)
k = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else '.')
spec = json.loads((k / 'fixture-spec.json').read_text())
report = {}
for name, s in spec['captures'].items():
    b = (k / name).read_bytes()
    require(hashlib.sha256(b).hexdigest() == s['sha256'], 'unapproved bytes: ' + name)
    p = subprocess.run(['tshark', '-r', str(k / name), '-d', 'tcp.port==17452,nbss', '-Y', 'smb2', '-T', 'fields', '-E', 'separator=,', '-E', 'header=y', '-E', 'quote=d', '-e', 'frame.number', '-e', 'smb2.cmd', '-e', 'smb2.msg_id', '-e', 'smb2.flags.response', '-e', 'smb2.nt_status', '-e', 'smb2.response_to'], capture_output=True, text=True)
    require(p.returncode == 0, p.stderr)
    rows = list(csv.DictReader(io.StringIO(p.stdout)))
    f = {int(r['frame.number']): r for r in rows}
    if name == 'practice.pcap':
        for req, resp, cmd in [(10, 11, 1), (12, 13, 3), (14, 15, 5), (18, 19, 8), (20, 21, 6), (24, 25, 3), (26, 27, 5), (28, 29, 9), (30, 31, 6)]:
            a, z = (f[req], f[resp])
            require(a['smb2.cmd'] == z['smb2.cmd'] == str(cmd), 'Fixture validation failed')
            require(a['smb2.msg_id'] == z['smb2.msg_id'], 'Fixture validation failed')
            require(a['smb2.flags.response'] == 'False' and z['smb2.flags.response'] == 'True', 'Fixture validation failed')
            require(z['smb2.nt_status'] == '0x00000000' and z['smb2.response_to'] == str(req), 'Fixture validation failed')
    else:
        require(28 in f and 29 not in f and (f[28]['smb2.flags.response'] == 'False') and (not any((r['smb2.flags.response'] == 'True' and r['smb2.msg_id'] == f[28]['smb2.msg_id'] for r in rows))), 'Fixture validation failed')
    report[name] = {'sha256': s['sha256'], 'decodedSmbMessages': len(rows), 'exactApprovedIdentity': True}
print(json.dumps({'state': 'PASS', 'captures': report}, indent=2))
