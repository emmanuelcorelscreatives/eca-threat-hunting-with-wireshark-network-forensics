from pathlib import Path
import os,sys,subprocess,time,json,hashlib
w=Path('/var/lib/trejj-studio/maintenance/wireshark-pocket-production-20261111');pid=sys.argv[1];r=w/'stage9l2-fullkit-v1'/('native-v4-'+sys.argv[2]);r.mkdir(parents=True);profile=r/'profile';profile.mkdir();capture=w/'stage9l2-fullkit-v1/kit/fixtures'/(sys.argv[2]+'.pcap');source=capture.read_bytes();binary=w/'native-wireshark-4.6.9-source-v1/build/run/wireshark';env=dict(os.environ,XDG_CONFIG_HOME=str(profile),WIRESHARK_CONFIG_DIR=str(profile/'wireshark'),QT_STYLE_OVERRIDE='Fusion',QT_QPA_PLATFORM='xcb',TZ='UTC');p=subprocess.Popen([str(binary),'--log-level','error','-o','capture.no_interface_load:TRUE','-r',str(capture)],env=env,stdout=(r/'app.stdout').open('w'),stderr=(r/'app.stderr').open('w'));records=[]
def cmd(*a):return subprocess.run(['xdotool',*a],capture_output=True,text=True,check=True).stdout
def wins():return subprocess.run(['xdotool','search','--onlyvisible','--pid',str(p.pid)],capture_output=True,text=True).stdout.split()
def focus():cmd('windowfocus','--sync',main)
def shot(n,role):
 f=r/(n+'.png');subprocess.run(['ffmpeg','-nostdin','-loglevel','error','-f','x11grab','-video_size','1536x864','-i',os.environ['DISPLAY'],'-frames:v','1','-threads','1',str(f)],check=True);records.append({'file':f.name,'sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'role':role,'visibleWindows':[{'id':v,'name':cmd('getwindowname',v).strip()}for v in wins()]});(r/'progress.json').write_text(json.dumps({'projectId':pid,'records':records},indent=2))
def paste(t):subprocess.run(['xclip','-selection','clipboard','-i'],input=t.encode(),check=True);cmd('key','ctrl+v');time.sleep(.3)
def filter_(t):focus();cmd('key','ctrl+slash');cmd('key','ctrl+a');paste(t);cmd('key','Return');time.sleep(.7);cmd('key','Escape');cmd('mousemove','1500','820')
def stat(index,title):
 focus();cmd('key','alt+s');time.sleep(.15);cmd('key','Home')
 for _ in range(index):cmd('key','Down')
 cmd('key','Return');time.sleep(.6);v=[v for v in wins()if title in cmd('getwindowname',v)]
 if not v:raise RuntimeError('Actual dialog missing '+title)
 cmd('windowsize',v[-1],'1536','864');cmd('windowmove',v[-1],'0','0');cmd('windowfocus','--sync',v[-1]);time.sleep(.3)
def close():cmd('key','Escape');time.sleep(.2);focus()
try:
 for _ in range(100):
  ids=wins()
  if ids:break
  if p.poll()is not None:raise RuntimeError((r/'app.stderr').read_text())
  time.sleep(.1)
 else:raise RuntimeError('No native window')
 main=ids[-1];cmd('windowsize',main,'1536','864');cmd('windowmove',main,'0','0');focus();time.sleep(2)
 filter_('');stat(6,'Graph');cmd('mousemove','42','742');cmd('click','1');cmd('mousemove','245','724');cmd('click','--repeat','2','--delay','120','1');cmd('key','ctrl+a');paste('NXDOMAIN replies');cmd('key','Return');cmd('mousemove','354','724');cmd('click','--repeat','2','--delay','120','1');cmd('key','ctrl+a');paste('dns.flags.response == 1 && dns.flags.rcode == 3');cmd('key','Return')
 cmd('mousemove','414','705');cmd('mousedown','1');cmd('mousemove','900','705');cmd('mouseup','1');time.sleep(.3);cmd('mousemove','1490','820');shot('01-failure-graph-1sec-full-filter','Actual NXDOMAIN-only graph with full expression and 1secondinterval visible; inspect actual table and counts')
 cmd('mousemove','1040','811');cmd('click','1');cmd('key','Up','Up');cmd('key','Return');time.sleep(.5);cmd('mousemove','1490','820');shot('02-failure-graph-200ms','Actual selected200ms equalinterval NXDOMAIN-only graph; visible filter/table/axis; inspect actual short interval rather than inferred setting')
 cmd('key','Escape');time.sleep(.3)
 assert source==capture.read_bytes();(r/'captured.json').write_text(json.dumps({'at':__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),'projectId':pid,'sourceCapturePath':str(capture),'sourceCaptureSha256':hashlib.sha256(source).hexdigest(),'sourcePreserved':True,'liveCaptureStarted':False,'actualPlatform':'Ubuntu24.04 nativeLinuxQtWireshark4.6.9 isolatedXvfb/profile','records':records,'scope':'Raw evidence only; independent review required.'},indent=2));print(json.dumps({'projectId':pid,'views':len(records)}))
except Exception as e:(r/'error.json').write_text(json.dumps({'error':str(e),'records':records,'automaticRetry':False},indent=2));raise
finally:
 p.terminate()
 try:p.wait(timeout=10)
 except subprocess.TimeoutExpired:p.kill();p.wait()
