import json,pathlib,sys,hashlib
r=pathlib.Path(__file__).parent
if len(sys.argv)!=3:raise SystemExit('Usage: python3 tune.py freeze NEW_PROPOSAL.json | holdout EXISTING_PROPOSAL.json')
mode,out=sys.argv[1],pathlib.Path(sys.argv[2]);e=json.loads((r/'actual-verification.json').read_text());training=[x for x in e['cases'] if x['partition']=='training'];bounds={'workstation':7,'backup':18}
def outcomes(rows):
 return [dict(case_id=x['case_id'],label=x['label'],events=x['events'],current='unobservable' if not x['observable'] else ('flag' if x['events']>5 else 'no match'),proposed='unobservable' if not x['observable'] else ('flag' if x['events']>bounds[x['asset_role']] else 'no match')) for x in rows]
if mode=='freeze':
 d={'provisional':True,'comparison':'> strictly greater than boundary','currentGlobalBoundary':5,'proposedRoleBoundaries':bounds,'windowSeconds':60,'unit':'UDP datagrams sent','training':outcomes(training),'holdoutUsedForTuning':False,'basis':'B01/B02 workstation 4/6; B03/B04 backup 12/16. Single fixed illustrative proposal; no search over holdout.'}
 with out.open('x') as f:json.dump(d,f,indent=2)
 print(json.dumps(d,indent=2))
elif mode=='holdout':
 d=json.loads(out.read_text());assert d['holdoutUsedForTuning'] is False and d['proposedRoleBoundaries']==bounds
 print(json.dumps({'proposalSha256':hashlib.sha256(out.read_bytes()).hexdigest(),'holdout':outcomes([x for x in e['cases'] if x['partition']=='holdout']),'decision':'H02 is a measurable miss under the provisional backup threshold; do not retune using holdout and claim independence.'},indent=2))
else:raise SystemExit('Unknown mode')
