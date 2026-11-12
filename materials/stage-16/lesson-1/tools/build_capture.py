#!/usr/bin/env python3
"""Offline deterministic fixture builder. Standard library only; no sockets opened."""
import argparse,json,struct,socket,datetime,pathlib

def checksum(b):
 if len(b)%2:b+=b"\0"
 n=sum(struct.unpack("!%dH"%(len(b)//2),b));n=(n&65535)+(n>>16);n=(n&65535)+(n>>16)
 return (~n)&65535

def label(s):return b"".join(bytes([len(x)])+x.encode("ascii") for x in s.split("."))+b"\0"
def timestamp(s):return int(datetime.datetime.fromisoformat(s.replace("Z","+00:00")).timestamp()*1000000)
def build(d):
 roles=d["roles"];events=[]
 def packet(us,src,dst,proto,segment,ident):
  a=socket.inet_aton(src);b=socket.inet_aton(dst)
  pseudo=a+b+struct.pack("!BBH",0,proto,len(segment))
  pos=16 if proto==6 else 6
  v=checksum(pseudo+segment);segment=segment[:pos]+struct.pack("!H",v or (65535 if proto==17 else 0))+segment[pos+2:]
  header=struct.pack("!BBHHHBBH4s4s",69,0,20+len(segment),ident,16384,64,proto,0,a,b)
  header=header[:10]+struct.pack("!H",checksum(header))+header[12:]
  eth=bytes.fromhex("0200000000020200000000010800") if src==roles["client"] else bytes.fromhex("0200000000010200000000020800")
  events.append((us,eth+header+segment))
 dns=d["dnsDesign"];q=label(dns["name"])+struct.pack("!HH",1,1)
 for response in [False,True]:
  body=struct.pack("!HHHHHH",dns["transactionId"],33152 if response else 256,1,2 if response else 0,0,0)+q
  if response:
   for role in dns["answers"]:body+=bytes.fromhex("c00c00010001")+struct.pack("!IH",dns["ttlSeconds"],4)+socket.inet_aton(roles[role])
  sp,dp=(53,dns["clientPort"]) if response else (dns["clientPort"],53)
  udp=struct.pack("!HHHH",sp,dp,8+len(body),0)+body
  packet(timestamp(dns["responseUtc"] if response else dns["queryUtc"]),roles["resolver"] if response else roles["client"],roles["client"] if response else roles["resolver"],17,udp,len(events)+1)
 for session in d["sessionDesigns"]:
  for event in session["packetPlan"]:
   forward=event["from"]=="client";src=roles["client"] if forward else roles[session["peer"]];dst=roles[session["peer"]] if forward else roles["client"]
   sp,dp=(session["clientPort"],session["peerPort"]) if forward else (session["peerPort"],session["clientPort"])
   flags=sum({"F":1,"S":2,"R":4,"P":8,"A":16}[f] for f in event["flags"])
   segment=struct.pack("!HHIIBBHHH",sp,dp,event["seq"],event["ack"],80,flags,65535,0,0)+event.get("payloadText","").encode("ascii")
   packet(timestamp(session["startUtc"])+event["offsetMs"]*1000,src,dst,6,segment,len(events)+1)
 out=struct.pack("<IHHIIII",0xa1b2c3d4,2,4,0,0,65535,1)
 for us,b in sorted(events,key=lambda x:x[0]):out+=struct.pack("<IIII",us//1000000,us%1000000,len(b),len(b))+b
 return out
if __name__=="__main__":
 a=argparse.ArgumentParser();a.add_argument("--scenario",required=True);a.add_argument("--output",required=True);args=a.parse_args();d=json.loads(pathlib.Path(args.scenario).read_text())
 if not d.get("synthetic") or d.get("schema")!="academy-weak-indicator-design-v1":raise SystemExit("Unsupported explicit synthetic design")
 with open(args.output,"xb") as f:f.write(build(d))
