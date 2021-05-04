import os
from pathlib import Path
from xml.dom import minidom
import xmltodict
import json

mfile = Path('output.txt')
if mfile.exists():
    manifest = mfile.read_text('utf-8', 'ignore')
else:
    manifest = ''

# doc = xmltodict.parse(manifest)
# with open('output.json','w',encoding='utf-8') as f:
#     f.write(json.dumps(json.loads(manifest)))
print(list(mfile.parent.iterdir())[0].as_posix())