# -*- coding: utf_8 -*-
"""Module holding the functions for code analysis."""

import logging
from pathlib import Path

from django.conf import settings

from  securityanalyzer.utils import filename_from_path
from StaticAnalyzer.views.shared_func import url_n_email_extract
from .sast_engine import scan

logger = logging.getLogger(__name__)


def code_analysis(app_dir, typ):
    """对代码执行词法分析并提取url与email"""
    try:
        logger.info('Code Analysis Started')
        root = settings.BASE_DIR / 'StaticAnalyzer' / 'views'
        code_rules = root / 'rules' / 'android_rules.yaml'
        code_findings = {}
        email_n_file = []
        url_n_file = []
        url_list = []
        app_dir = Path(app_dir)
        if typ == 'apk':
            src = app_dir / 'java_source'
        elif typ == 'studio':
            src = app_dir / 'app' / 'src' / 'main' / 'java'
            kt = app_dir / 'app' / 'src' / 'main' / 'kotlin'
            if not src.exists() and kt.exists():
                src = kt
        elif typ == 'eclipse':
            src = app_dir / 'src'
        else:
            src = app_dir
        src = src.as_posix() + '/'
        skp = settings.SKIP_CLASS_PATH
        logger.info('Code Analysis Started on - %s',
                    filename_from_path(src))
        # Code and API Analysis
        code_findings = scan(
            code_rules.as_posix(),
            {'.java', '.kt'},
            [src],
            skp)
        # 提取 URLs and Emails
        for pfile in Path(src).rglob('*'):
            if (
                #后缀
                (pfile.suffix in ('.java', '.kt')
                    and any(skip_path in pfile.as_posix()
                            for skip_path in skp) is False)
            ):
                content = None
                try:
                    content = pfile.read_text('utf-8', 'ignore')
                    # Certain file path cannot be read in windows
                except Exception:
                    continue
                relative_java_path = pfile.as_posix().replace(src, '')
                urls, urls_nf, emails_nf = url_n_email_extract(
                    content, relative_java_path)
                url_list.extend(urls)
                url_n_file.extend(urls_nf)
                email_n_file.extend(emails_nf)
        logger.info('Finished Code Analysis, Email and URL Extraction')
        code_an_dic = {
            'findings': code_findings,
            'urls_list': url_list,
            'urls': url_n_file,
            'emails': email_n_file,
        }
        return code_an_dic
    except Exception:
        logger.exception('Performing Code Analysis')
