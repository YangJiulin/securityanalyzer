# -*- coding: utf_8 -*-
"""
Shared Functions.
"""
import logging
import os
import platform
import re

from django.conf import settings
from django.shortcuts import redirect
from securityanalyzer.utils import print_n_send_error_response
import shutil
import subprocess
import zipfile
from urllib.parse import urlparse
from pathlib import Path
from django.utils import timezone
from django.utils.html import escape

from StaticAnalyzer.models import RecentScansDB
from StaticAnalyzer.views.db_operation import (
    get_info_from_db_entry as adb)

logger = logging.getLogger(__name__)
ctype = 'application/json; charset=utf-8'


def url_n_email_extract(dat, relative_path):
    """Extract URLs and Emails from Source Code."""
    urls = []
    emails = []
    urllist = []
    url_n_file = []
    email_n_file = []
    # URLs Extraction My Custom regex
    pattern = re.compile(
        (
            r'((?:https?://|s?ftps?://|'
            r'file://|javascript:|data:|www\d{0,3}[.])'
            r'[\w().=/;,#:@?&~*+!$%\'{}-]+)'
        ),
        re.UNICODE)
    urllist = re.findall(pattern, dat)
    uflag = 0
    for url in urllist:
        if url not in urls:
            urls.append(url)
            uflag = 1
    if uflag == 1:
        url_n_file.append(
            {'urls': urls, 'path': escape(relative_path)})

    # Email Extraction Regex
    regex = re.compile(r'[\w.-]{1,20}@[\w-]{1,20}\.[\w]{2,10}')
    eflag = 0
    for email in regex.findall(dat.lower()):
        if (email not in emails) and (not email.startswith('//')):
            emails.append(email)
            eflag = 1
    if eflag == 1:
        email_n_file.append(
            {'emails': emails, 'path': escape(relative_path)})
    return urllist, url_n_file, email_n_file

def update_scan_timestamp(scan_hash):
    # Update the last scan time.
    tms = timezone.now()
    RecentScansDB.objects.filter(MD5=scan_hash).update(TIMESTAMP=tms)


def find_java_source_folder(base_folder: Path):
    # 找到APK或者源代码zip的java/kotlin文件
    # 返回一个元组(SRC_PATH, SRC_TYPE, SRC_SYNTAX)
    return next(p for p in [(base_folder / 'java_source',
                             'java', '*.java'),
                            (base_folder / 'app' / 'src' / 'main' / 'java',
                             'java', '*.java'),
                            (base_folder / 'app' / 'src' / 'main' / 'kotlin',
                             'kotlin', '*.kt'),
                            (base_folder / 'src',
                             'java', '*.java')]
                if p[0].exists())


def run(request):
    """下载apk或者Java源代码"""
    try:
        logger.info('Generating Downloads')
        md5 = request.GET['hash']
        file_type = request.GET['file_type']
        match = re.match('^[0-9a-f]{32}$', md5)
        if not match and file_type not in ['apk','java']:
            logger.exception('Invalid options')
            return print_n_send_error_response(request,
                                               'Invalid options')
        app_dir = os.path.join(settings.MEDIA_ROOT / 'upload', md5)
        file_name = ''
        if file_type == 'java':
            # For Java
            file_name = md5 + '-java'
            directory = os.path.join(app_dir, 'java_source/')
            dwd_dir = os.path.join(settings.DWD_DIR / md5, file_name)
            shutil.make_archive(dwd_dir, 'zip', directory)
            file_name = file_name + '.zip'
        elif file_type == 'apk':
            file_name = md5 + '.apk'
            src = os.path.join(app_dir, file_name)
            dst = os.path.join(settings.DWD_DIR / md5, file_name)
            shutil.copy2(src, dst)
        return redirect('/download/' + md5+'/' + file_name)
    except Exception:
        logger.exception('Generating Downloads')
        return print_n_send_error_response(request,
                                           'Generating Downloads')
