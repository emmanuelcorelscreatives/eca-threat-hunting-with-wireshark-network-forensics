#!/usr/bin/env python3
from pathlib import Path
import subprocess,sys
root=Path(__file__).resolve().parent
args=sys.argv[1:]
if '--spec' not in args:args=['--spec',str(root/'fixture-spec.json')]+args
subprocess.run([sys.executable,str(root/'offline-builder.py')]+args,check=True)
