import os
from pathlib import Path
from signal import signal
import subprocess
from time import time
from xml.dom import minidom
import json
import signal

import psutil

mfile = Path('output.txt')
if mfile.exists():
    manifest = mfile.read_text('utf-8', 'ignore')
else:
    manifest = ''

# doc = xmltodict.parse(manifest)
# with open('output.json','w',encoding='utf-8') as f:
#     f.write(json.dumps(json.loads(manifest)))
import time
def start_proxy(port):
    """Start HTTPtools in Proxy Mode."""
    argz = ['lyrebird','-b',
            '--mock', '9090',
            '--proxy', str(port)]
    print(' '.join(argz))
    fnull = open(os.devnull, 'w')
    process = subprocess.Popen(argz, stdout=fnull, stderr=subprocess.STDOUT)
    return process.pid

pid = start_proxy('4272')
print(pid)
# time.sleep(3)
# os.kill(pid,signal.SIGKILL)
