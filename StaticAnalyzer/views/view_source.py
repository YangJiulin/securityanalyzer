# -*- coding: utf_8 -*-
"""查看文件源码"""

import logging
import ntpath
from pathlib import Path

from django.conf import settings
from django.shortcuts import render
from django.utils.html import escape

from Home.forms import FormUtil
from securityanalyzer.utils import (
    is_safe_path,
    print_n_send_error_response,
)
from StaticAnalyzer.views.shared_func import (
    find_java_source_folder,
)
from StaticAnalyzer.forms import (
    ViewSourceAndroidForm,
)

logger = logging.getLogger(__name__)


def run(request):
    """View the source of a file."""
    #http://127.0.0.1:8000/view_file/?
    # file=com/umeng/analytics/pro/q.java&
    # md5=09af06a1dbe94dfc58e92d4f12e526c7&
    # type=apk&
    # lines=355,19
    try:
        logger.info('查看文件源码')
        exp = '错误描述'
        fil = request.GET['file']
        md5 = request.GET['md5']
        typ = request.GET['type']
        viewsource_form = ViewSourceAndroidForm(request.GET)
        if not viewsource_form.is_valid():
            err = FormUtil.errors_message(viewsource_form)
            return print_n_send_error_response(request, err, False,exp)
        base = Path(settings.MEDIA_ROOT)/ 'upload' / md5
        if typ == 'smali':
            src = base / 'smali_source'
            syntax = 'smali'
        else:
            try:
                src, syntax, _ = find_java_source_folder(base)
            except StopIteration:
                msg = 'Invalid Directory Structure'
                return print_n_send_error_response(request, msg, False)

        sfile = src / fil
        if not is_safe_path(src, sfile.as_posix()):
            msg = 'Path Traversal Detected!'
            return print_n_send_error_response(request, msg, False)
        context = {
            'title': escape(ntpath.basename(fil)),
            'file': escape(ntpath.basename(fil)),
            'data': sfile.read_text('utf-8', 'ignore'),
            'type': syntax,
            'sqlite': {},
        }
        template = 'general/view.html'
        return render(request, template, context)
    except Exception as exp:
        logger.exception('Error Viewing Source')
        msg = str(exp)
        exp = exp.__doc__
        return print_n_send_error_response(request, msg, False, exp)
