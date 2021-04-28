from pathlib import Path
from xml.dom import minidom

mfile = Path('out.xml')
if mfile.exists():
    manifest = mfile.read_text('utf-8', 'ignore')
else:
    manifest = ''
manifest = minidom.parseString(manifest)
Result = manifest.getElementsByTagName('Results')[0]
res = []
for node in Result.childNodes:
    if node.nodeName == 'Result':
        val = {}
        val['source']=[]
        val['sink']=node.getElementsByTagName('Sink')[0].getAttribute('Method')
        for source in node.getElementsByTagName('Source'):
            val['source'].append({
                'method':source.getAttribute('Method'),
                'statement':source.getAttribute('Statement')
            })
        res.append(val)
for i in res:
    print(i,end='\n')