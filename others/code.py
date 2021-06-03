import ast
import json

from django.forms import widgets


# with open('/Users/nine/VSCode/python-project/securityanalyzer/others/code.txt','r') as f:
#     # data = json.dumps(f.read())
   
#     data = ast.literal_eval(f.read())
#     with open('code.json','w') as t:
#         t.write(json.dumps(data))
#     print(1)

a = {'file':{
    'sf':5,
    'sy':6,
    'we':9
}}

print(len(a['file']))