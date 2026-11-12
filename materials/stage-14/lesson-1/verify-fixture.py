import pathlib,hashlib,subprocess,json
p=pathlib.Path(__file__).parent/'fixtures/tls13-visible-handshake-supplemental.pcapng'
expected='2a0d510210b9177212533252d772da1a3810f167d3675d87b603974ff6f22e90'
if hashlib.sha256(p.read_bytes()).hexdigest()!=expected: raise SystemExit('FAIL: capture SHA mismatch')
def fields(f,cols):
 return subprocess.check_output(['tshark','-r',str(p),'-Y',f,'-T','fields',*[x for c in cols for x in ['-e',c]]],text=True).strip().splitlines()
a=fields('tls.handshake.type == 1 || tls.handshake.type == 2',['frame.number','tcp.stream','tls.handshake.type','tls.handshake.extensions.supported_version'])
if a!=['4\t0\t1\t0x0304','6\t0\t2\t0x0304']: raise SystemExit('FAIL: hello fields')
b=fields('tls.record.opaque_type == 23',['frame.number'])
if b!=['6','8','9','10','13','14']: raise SystemExit('FAIL: opaque packet list')
print(json.dumps({'verdict':'pass','captureSHA256':expected,'helloRows':a,'opaqueFrames':b,'scope':'exact supplied supplemental capture identity and decoded hello/outer fields only'}))
