# -*- coding: utf_8 -*-
"""Module holding the functions for converting."""

import glob
import logging
import os
import platform
import shutil
import subprocess
import tempfile
import threading
import stat

from django.conf import settings

from  securityanalyzer.utils import find_java_binary


logger = logging.getLogger(__name__)


def apk_2_java(app_path, app_dir, tools_dir):
    """运行 jadx."""
    try:
        logger.info('APK -> JAVA')
        output = os.path.join(app_dir, 'java_source/')
        logger.info('Decompiling to Java with jadx')

        if os.path.exists(output):
            # ignore WinError3 in Windows
            shutil.rmtree(output, ignore_errors=True)

        if platform.system() == 'Windows':
            jadx = os.path.join(tools_dir, 'jadx/bin/jadx.bat')
        else:
            jadx = os.path.join(tools_dir, 'jadx/bin/jadx')
        # 如果jadx没有执行权限，给其设置执行权限
        if not os.access(jadx, os.X_OK):
            os.chmod(jadx, stat.S_IRWXU)
        args = [
            jadx,
            '-ds',
            output,
            '-q',
            '-r',
            '--show-bad-code',
            app_path,
        ]
        fnull = open(os.devnull, 'w')
        subprocess.call(args,
                        stdout=fnull,
                        stderr=subprocess.STDOUT)
    except Exception:
        logger.exception('Decompiling to JAVA')

def unzip_apk_apktool(app_path, app_dir, tools_dir):
    """使用apktool解压apk"""
    try:
        apktool_path = os.path.join(tools_dir, 'apktool_2.5.0.jar')
        output_dir = os.path.join(app_dir, 'apktool_out')
        args = [find_java_binary(),
                '-jar',
                apktool_path,
                '--match-original',
                '--frame-path',
                tempfile.gettempdir(),
                '-f', '-s', 'd',
                app_path,
                '-o',
                output_dir]
        logger.info('Converting AXML to XML')
        subprocess.check_output(args)
        logger.info('转换完成')
    except Exception:
        logger.exception('Getting Manifest file')