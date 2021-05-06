# -*- coding: utf_8 -*-
"""Dynamic Analyzer Reporting."""
import logging
import ntpath
import os
import io

from django.conf import settings
from django.shortcuts import render
from django.template.defaulttags import register
from django.utils.html import escape

from DynamicAnalyzer.views.analysis import (
    generate_download,
    get_screenshots,
    run_analysis,
)
from DynamicAnalyzer.views.operations import (
    get_package_name,
    is_path_traversal,
)
from DynamicAnalyzer.views.tests_frida import (
    apimon_analysis,
)
from securityanalyzer.utils import (
    is_file_exists,
    is_md5,
    is_safe_path,
    print_n_send_error_response,
    read_sqlite,
)


logger = logging.getLogger(__name__)


@register.filter
def key(d, key_name):
    """To get dict element by key name in template."""
    return d.get(key_name)


def view_report(request, checksum):
    """Dynamic Analysis Report Generation."""
    logger.info('Dynamic Analysis Report Generation')
    try:
        droidmon = {}
        apimon = {}
        if not is_md5(checksum):
            # We need this check since checksum is not validated
            return print_n_send_error_response(
                request,
                'Invalid Parameters',)
        package = get_package_name(checksum)
        if not package:
            return print_n_send_error_response(
                request,
                'Invalid Parameters')
        app_dir = os.path.join(settings.MEDIA_ROOT / 'upload', checksum + '/')
        download_dir = settings.DWD_DIR
        if not is_file_exists(os.path.join(app_dir, 'logcat.txt')):
            msg = ('Dynamic Analysis report is not available '
                   'for this app. Perform Dynamic Analysis '
                   'and generate the report.')
            return print_n_send_error_response(request, msg)
        fd_log = os.path.join(app_dir, 'frida_out.txt')
        droidmon = []
        # droidmon_api_analysis(app_dir, package)
        apimon = apimon_analysis(app_dir)
        analysis_result = run_analysis(app_dir, checksum, package)
        generate_download(app_dir, checksum, download_dir, package)
        images = get_screenshots(checksum, download_dir)
        context = {'hash': checksum,
                   'emails': analysis_result['emails'],
                   'urls': analysis_result['urls'],
                   'xml': analysis_result['xml'],
                   'sqlite': analysis_result['sqlite'],
                   'others': analysis_result['other_files'],
                   'screenshots': images['screenshots'],
                   'exported_activity_tester': images['exported_activities'],
                   'droidmon': droidmon,
                   'apimon': apimon,
                   'frida_logs': is_file_exists(fd_log),
                   'package': package,
                   'title': 'Dynamic Analysis'}
        template = 'dynamic_analysis/android/dynamic_report.html'
        return render(request, template, context)
    except Exception as exp:
        logger.exception('Dynamic Analysis Report Generation')
        err = 'Error Geneating Dynamic Analysis Report. ' + str(exp)
        return print_n_send_error_response(request, err)


def view_file(request):
    """View File."""
    logger.info('Viewing File')
    try:
        typ = ''
        rtyp = ''
        dat = ''
        sql_dump = {}
        fil = request.GET['file']
        md5_hash = request.GET['hash']
        typ = request.GET['type']
        if not is_md5(md5_hash):
            return print_n_send_error_response(request,
                                               'Invalid Parameters',
                                               )
        src = os.path.join(
            settings.MEDIA_ROOT / 'upload',
            md5_hash,
            'DYNAMIC_DeviceData/')
        sfile = os.path.join(src, fil)
        if not is_safe_path(src, sfile) or is_path_traversal(fil):
            err = 'Path Traversal Attack Detected'
            return print_n_send_error_response(request, err)
        with io.open(sfile, mode='r', encoding='ISO-8859-1') as flip:
            dat = flip.read()
        if fil.endswith('.xml') and typ == 'xml':
            rtyp = 'xml'
        elif typ == 'db':
            dat = None
            sql_dump = read_sqlite(sfile)
            rtyp = 'asciidoc'
        elif typ == 'others':
            rtyp = 'asciidoc'
        else:
            err = 'File type not supported'
            return print_n_send_error_response(request, err)
        fil = escape(ntpath.basename(fil))
        context = {
            'title': fil,
            'file': fil,
            'data': dat,
            'sqlite': sql_dump,
            'type': rtyp,
        }
        template = 'general/view.html'
        return render(request, template, context)
    except Exception:
        logger.exception('Viewing File')
        return print_n_send_error_response(
            request,
            'Error Viewing File')
