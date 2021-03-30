# -*- coding: utf_8 -*-
"""Android Static Code Analysis."""

import logging
import os
import json
import re
import shutil
from pathlib import Path

from django.conf import settings
from django.http import HttpResponseRedirect
from django.http.response import HttpResponse
from django.shortcuts import render
from django.template.defaulttags import register

from androguard.core.bytecodes import apk    
from StaticAnalyzer.models import StaticAnalyzerAndroid

logger = logging.getLogger(__name__)


@register.filter
def key(data, key_name):
    """Return the data for a key_name."""
    return data.get(key_name)


def static_analyzer(request):
    typ = request.GET['type']
    checksum = request.GET['checksum']
    filename = request.GET['name']
    rescan = str(request.GET.get('rescan', 0))

    app_info = {}
    match = re.match('^[0-9a-f]{32}$', checksum)
    if (match and filename.lower().endswith(('.apk', '.zip'))and typ in ['zip', 'apk']):
        app_info['dir'] = settings.BASE_DIR  # BASE DIR
        app_info['app_name'] = filename  # APP ORGINAL NAME
        app_info['md5'] = checksum  # MD5
        # APP DIRECTORY
        app_info['app_dir'] = settings.MEDIA_ROOT / 'upload' / checksum   #APK所在文件夹路径
        app_info['tools_dir'] = app_info['dir'] / 'StaticAnalyzer' / 'tools'
        app_info['tools_dir'] = app_info['tools_dir'].as_posix()
        logger.info('开始分析 : %s' , app_info['app_name'])
        if typ == 'apk':
                app_info['app_file'] = app_info['md5'] + '.apk'  # NEW FILENAME
                app_info['app_path'] = (
                    app_info['app_dir'] / app_info['app_file']).as_posix()    #apk文件路径
                app_info['app_dir'] = app_info['app_dir'].as_posix() + '/'
                _apk = apk.APK(app_info['app_path'])
                # Check if in DB
                # pylint: disable=E1101
                # db_entry = StaticAnalyzerAndroid.objects.filter(
                #     MD5=app_info['md5']).update(PACKAGE_NAME = _apk.get_package(),
                #     VERSION_NAME = _apk.get_androidversion_name(),
                #     APP_NAME = _apk.get_app_name()
                #     )
    template = 'static_analysis/android_binary_analysis.html'
    # return render(request, template, context={})
    return HttpResponse(json.dumps('success'))