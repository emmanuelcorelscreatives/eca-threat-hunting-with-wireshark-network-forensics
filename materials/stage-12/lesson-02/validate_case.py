#!/usr/bin/env python3
"""Read-only standard-library validation of the supplied synthetic CSV case."""
import argparse,csv,datetime,hashlib,ipaddress,json,pathlib,sys

def check(d):
    controls=json.loads((d/'controls.json').read_text())['files']; data={}
    for name,c in controls.items():
        assert pathlib.PurePosixPath(name).name==name and name.endswith('.csv'), 'unsafe control filename'
        raw=(d/name).read_bytes(); reader=csv.DictReader(raw.decode('utf-8').splitlines()); rows=list(reader)
        assert reader.fieldnames==c['header'], name+': schema'
        assert len(rows)==c['rows'] and all(None not in r and all(v is not None for v in r.values()) for r in rows), name+': row shape/count'
        ids=[r[c['header'][0]] for r in rows]; assert len(set(ids))==len(ids), name+': duplicate identifier'
        assert hashlib.sha256(raw).hexdigest()==c['sha256'], name+': frozen bytes differ'
        data[name]=rows
    def utc(s):
        assert s.endswith('Z'), 'UTC Z required'
        return datetime.datetime.strptime(s,'%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=datetime.timezone.utc)
    exchanges=data['synthetic_auth_exchanges.csv']; events=data['synthetic_identity_events.csv']; changes=data['synthetic_change_records.csv']; env=data['synthetic_environment_map.csv']
    known={r['ip'] for r in env}; accounts={r['account'] for r in exchanges}
    for address in known:
        ip=ipaddress.ip_address(address); assert any(ip in ipaddress.ip_network(n) for n in ('192.0.2.0/24','198.51.100.0/24','203.0.113.0/24')), 'non-documentation IP'
    for rows,key in ((exchanges,'request_utc'),(events,'event_utc'),(changes,'event_utc')):
        times=[utc(r[key]) for r in rows]; assert times==sorted(times), 'UTC ordering'
    for r in exchanges:
        assert r['src_ip'] in known and r['dst_ip'] in known, 'endpoint reference'
        t=utc(r['request_utc']); end=utc(r['response_utc']) if r['response_utc'] else None
        assert end is None or end>=t, 'response before request'
        n=int(r['modelled_request_resends']); assert n in (0,1), 'resend count'
        assert bool(n)==bool(r['repeat_time_utc']), 'resend time'
        if n: assert t<utc(r['repeat_time_utc']) and (end is None or utc(r['repeat_time_utc'])<end), 'resend ordering'
    for r in events:
        assert r['account'] in accounts, 'event account reference'
        if r['event_id_windows']=='4771': assert r['client_address'] in known and not r['source_workstation'], '4771 context'
        else: assert r['event_id_windows']=='4776' and not r['client_address'] and r['source_workstation'], '4776 context'
    for r in changes:
        assert r['account'] in accounts and r['host_ip'] in known and r['approved_source_ip'] in known, 'change reference'
        assert set(r['approved_destinations'].split('|'))<=known, 'destination reference'
    return {'verdict':'pass','synthetic':True,'exchangeRows':len(exchanges),'identityEvents':len(events),'changeRecords':len(changes),'mappedAddresses':len(env),'modelledResends':sum(int(r['modelled_request_resends']) for r in exchanges),'kerberosCode24':sum(r['protocol']=='Kerberos' and r['result_code']=='24' for r in exchanges),'ldapBind49':sum(r['response_kind']=='LDAP_BIND_RESPONSE' and r['result_code']=='49' for r in exchanges),'unresolvedNtlm':sum(r['protocol']=='NTLM' and r['response_kind']=='NOT_VISIBLE' for r in exchanges),'scope':'Exact supplied synthetic CSVs only; no packet or native-event validation'}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--case-dir',type=pathlib.Path,required=True);a=p.parse_args()
    try: print(json.dumps(check(a.case_dir),sort_keys=True))
    except Exception as e: print(json.dumps({'verdict':'fail','error':str(e)}));sys.exit(1)
