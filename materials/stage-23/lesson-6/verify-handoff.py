#!/usr/bin/env python3
"""Validate the supplied schema subset and training handoff gates; never evidence truth."""
import datetime,json,sys
from pathlib import Path

def schema_check(value,s,root,path='$'):
    if '$ref' in s:
        target=root
        for part in s['$ref'].removeprefix('#/').split('/'): target=target[part]
        schema_check(value,target,root,path)
    for sub in s.get('allOf',[]):schema_check(value,sub,root,path)
    if 'if' in s:
        try:schema_check(value,s['if'],root,path)
        except ValueError:pass
        else:schema_check(value,s.get('then',{}),root,path)
    if 'not' in s:
        try:schema_check(value,s['not'],root,path)
        except ValueError:pass
        else:raise ValueError(path+': forbidden value')
    types={'object':lambda x:isinstance(x,dict),'array':lambda x:isinstance(x,list),'string':lambda x:isinstance(x,str),'null':lambda x:x is None,'boolean':lambda x:type(x)is bool,'integer':lambda x:type(x)is int}
    if 'type' in s:
        ts=s['type'] if isinstance(s['type'],list) else [s['type']]
        if not any(types[k](value) for k in ts):raise ValueError(path+': wrong type')
    if 'const'in s and (type(value)is not type(s['const']) or value!=s['const']):raise ValueError(path+': wrong constant')
    if 'enum'in s and value not in s['enum']:raise ValueError(path+': invalid choice')
    if isinstance(value,dict):
        for k in s.get('required',[]):
            if k not in value:raise ValueError(path+': missing '+k)
        for k,sub in s.get('properties',{}).items():
            if k in value:schema_check(value[k],sub,root,path+'.'+k)
    if isinstance(value,list):
        if len(value)<s.get('minItems',0):raise ValueError(path+': too few items')
        for i,x in enumerate(value):schema_check(x,s.get('items',{}),root,path+'['+str(i)+']')
    if isinstance(value,str) and len(value)<s.get('minLength',0):raise ValueError(path+': too short')
    if type(value)is int and value<s.get('minimum',value):raise ValueError(path+': below minimum')

def validate(v):
    schema=json.loads(Path(__file__).with_name('plan-handoff-schema.json').read_text())
    schema_check(v,schema,schema)
    def need(ok,why):
        if not ok:raise ValueError(why)
    def named(x):return isinstance(x,str) and x.strip().lower() not in ('','unassigned','unknown')
    def date(x):
        try:datetime.date.fromisoformat(x);return True
        except (TypeError,ValueError):return False
    for role in ('detection','review','telemetry'):
        r=v['owners'][role]
        if r['accepted']:need(named(r['role']) and date(r['acceptance_date']) and named(r['reference']),'accepted role requires name, ISO date and evidence')
    for test in ('positive','delivery'):
        x=v['tests'][test]
        if x['actual']!='unrun':need(named(x['expected']) and named(x['source_ref']),'executed test requires prior expectation and source reference')
    ids=[x['id'] for x in v['blind_spots']];need(len(ids)==len(set(ids)),'gap IDs must be unique')
    priorities=[x['priority'] for x in v['blind_spots']];need(len(priorities)==len(set(priorities)),'gap priorities must be unique')
    for x in v['blind_spots']:
        if x['state']=='closed':need(named(x['acceptance_evidence_ref']),'closed gap needs its own evidence')
    r=v['reviews']
    if r['decision']!='pending' or r['proposal_owner_decision']!='pending':
        need(r['decision']==r['proposal_owner_decision'] and r['decision']!='pending','review decisions must agree and both indicate completion')
        need(named(r['owner']) and named(r['proposal_owner']) and named(r['trigger_route']),'completed review requires review owner, proposal owner and trigger route')
        need(named(r['reason']) and date(r['following_date']) and named(r['notification_ref']) and r['proposal_owner_decision']!='pending' and named(r['proposal_owner_decision_ref']),'review requires notification, documented proposal-owner decision and following date')
    if v['status']=='ready-for-approval':
        need(v['owners']['detection']['role']!=v['owners']['review']['role'],'detection and match-review roles must be distinct')
        for k in ('backup_contact','change_approver','missed_observation_investigator','source_failure_recipient'):need(named(v['owners'][k]),'missing responsibility '+k)
        need(named(v['tests']['positive']['destination']),'positive destination missing')
        need(v['tests']['scheduled_activity']['decision']!='undecided' and named(v['tests']['scheduled_activity']['evidence_ref']),'scheduled comparison incomplete')
        need(date(r['next_date']) and named(r['owner']) and named(r['proposal_owner']) and named(r['trigger_route']),'review route, owners and ISO date required')
        need(named(v['change_control']['reversible_response']),'reversible response missing')
    return {'valid':True,'status':v['status'],'meaning':'Structure and evidence-reference checks only; no operational truth or deployment approval'}
if __name__=='__main__':
    try:
        if len(sys.argv)!=2:raise ValueError('Usage: python3 verify-handoff.py learner-handoff.json')
        print(json.dumps(validate(json.loads(Path(sys.argv[1]).read_text()))))
    except (ValueError,KeyError,TypeError,OSError) as e:print(json.dumps({'valid':False,'error':str(e)}));sys.exit(1)


