import pathlib,subprocess,json,hashlib,struct
p=pathlib.Path(__file__).parent;cap=p/'controlled-tls-session.pcapng';keys=p/'controlled-tls-session.keys';rows=[]
for name,args in [('capinfos',['capinfos','-c','-a','-e','-u',str(cap)]),('before-tls',['tshark','-o','tls.keylog_file:','-r',str(cap),'-Y','tls','-T','fields','-e','frame.number','-e','tcp.stream','-e','ip.src','-e','ip.dst']),('before-http',['tshark','-o','tls.keylog_file:','-r',str(cap),'-Y','http or http2','-T','fields','-e','frame.number']),('after-http',['tshark','-o','tls.keylog_file:'+str(keys),'-r',str(cap),'-Y','http','-T','fields','-E','header=y','-E','separator=,','-e','frame.number','-e','tcp.stream','-e','ip.src','-e','ip.dst','-e','http.request.method','-e','http.request.uri','-e','http.response.code']),('follow-before',['tshark','-o','tls.keylog_file:','-r',str(cap),'-q','-z','follow,tls,ascii,0']),('follow-after',['tshark','-o','tls.keylog_file:'+str(keys),'-r',str(cap),'-q','-z','follow,tls,ascii,0'])]:
 r=subprocess.run(args,capture_output=True,text=True);assert r.returncode==0;(p/(name+'.txt')).write_text(r.stdout);rows.append({'name':name,'argv':args,'exitCode':r.returncode,'stdoutSha256':hashlib.sha256(r.stdout.encode()).hexdigest(),'stderr':r.stderr})
assert not (p/'before-http.txt').read_text().strip();s=(p/'after-http.txt').read_text();assert s.count('/academy/tls-check')==1 and s.count(',200')==1
b=cap.read_bytes();offset=0;types=[]
while offset<len(b):
 typ,size=struct.unpack_from('<II',b,offset);assert size>=12 and struct.unpack_from('<I',b,offset+size-4)[0]==size;types.append(typ);offset+=size
assert offset==len(b) and 10 not in types
(p/'verification.json').write_text(json.dumps({'checks':rows,'pcapngBlockTypes':types,'noDecryptionSecretsBlocks':True,'sameStreamBeforeAfter':True,'captureSha256':hashlib.sha256(b).hexdigest(),'keyLogSha256':hashlib.sha256(keys.read_bytes()).hexdigest()},indent=2))
print(s)
