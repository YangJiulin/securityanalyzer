from django.http import HttpResponse
import json
def tt(request):
    p = request.GET
    s = dict(p)
    return HttpResponse(json.dumps(s))