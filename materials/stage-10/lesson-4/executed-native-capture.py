from pathlib import Path
import os,sys,subprocess,time,json,hashlib
w=Path('/var/lib/trejj-studio/maintenance/wireshark-pocket-production-20261111');pid=sys.argv[1];r=w/'materials-s10l4-export-v1'/'gui-final';r.mkdir(parents=True);profile=r/'profile';profile.mkdir();capture=w/'materials-s10l4-export-v1'/'kit'/'practice.pcap';source=capture.read_bytes();binary=w/'native-wireshark-4.4.0-source-v1/build/run/wireshark';env=dict(os.environ,XDG_CONFIG_HOME=str(profile),WIRESHARK_CONFIG_DIR=str(profile/'wireshark'),QT_STYLE_OVERRIDE='Fusion',QT_QPA_PLATFORM='xcb',TZ='UTC');p=subprocess.Popen([str(binary),'--log-level','error','-o','capture.no_interface_load:TRUE','-r',str(capture)],env=env,stdout=(r/'app.stdout').open('w'),stderr=(r/'app.stderr').open('w'));records=[]
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
  time.sleep(.1)
 main=ids[-1];cmd('windowsize',main,'1536','864');cmd('windowmove',main,'0','0');focus();time.sleep(2)
 filter_('http.request || http.response');shot('01-http-filter','Actual native accepted HTTP request/response filter, both conversations')
 focus();cmd('key','alt+f');time.sleep(.3);cmd('mousemove','180','344');cmd('click','1');time.sleep(.5);cmd('mousemove','400','388');cmd('click','1');time.sleep(.6);shot('02-export-objects','Actual HTTP Export Objects dialog, inspect both rows and Packet column')
 cmd('mousemove','820','196');cmd('click','1');time.sleep(.2);shot('03-selected-target','Actual selected inert text row Packet7, 35bytes; Save one target')
 cmd('mousemove','741','629');cmd('click','1');time.sleep(.5);shot('04-save-dialog','Actual single-object Save dialog')
 cmd('key','ctrl+a');paste(str(r/'gui-saved-inert-training-object.txt'));cmd('key','Return');time.sleep(.7)
 cmd('mousemove','995','629');cmd('click','1');time.sleep(.3);focus();cmd('key','ctrl+g');paste('7');cmd('key','Return');time.sleep(.5);shot('05-go-packet7','Actual Go to Packet7 response after single-object export; source frame context')
 cmd('mousemove','400','528');cmd('click','1');cmd('key','End');cmd('key','Right');time.sleep(.4);shot('06-response-details','Actual response packet details after expansion; inspect visible HTTP/reassembly data')
 saved=r/'gui-saved-inert-training-object.txt';assert saved.read_bytes()==(w/'materials-s10l4-export-v1'/'kit'/'inert-training-object.txt').read_bytes()
 (r/'export-execution.json').write_text(json.dumps({'sourceCaptureSha256':hashlib.sha256(source).hexdigest(),'exportPath':str(saved),'exportBytes':len(saved.read_bytes()),'exportSha256':hashlib.sha256(saved.read_bytes()).hexdigest(),'equalsSourceObject':True,'singleObjectSave':True,'rawUiEvidence':'gui-final'},indent=2))
 (r/'captured.json').write_text(json.dumps({'projectId':pid,'sourceCapturePath':str(capture),'sourceCaptureSha256':hashlib.sha256(source).hexdigest(),'records':records,'sourcePreserved':source==capture.read_bytes(),'liveCaptureStarted':False},indent=2))
finally:
 p.terminate();p.wait(timeout=10)
