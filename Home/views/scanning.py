# -*- coding: utf_8 -*-
import hashlib
import logging
import os

from django.conf import settings
from django.utils import timezone

from StaticAnalyzer.models import StaticAnalyzerAndroid,RecentScansDB
from androguard.core.bytecodes import apk   
from config import settings 

logger = logging.getLogger(__name__)


def add_to_recent_scan(data):
    """将数据添加至最近扫描表."""
    try:
        db_obj = RecentScansDB.objects.filter(MD5=data['hash'])
        if not db_obj.exists():
            new_db_obj = RecentScansDB(
                ANALYZER=data['analyzer'],
                SCAN_TYPE=data['scan_type'],
                FILE_NAME=data['file_name'],
                APP_NAME=data.get('app_name',''),
                PACKAGE_NAME=data.get('packge_name',''),
                VERSION_NAME=data.get('version_name',''),
                MD5=data['hash'],
                TIMESTAMP=timezone.now())
            new_db_obj.save()
    except Exception:
        logger.exception('Adding Scan URL to Database')


def handle_uploaded_file(filecnt, typ):
    """Write Uploaded File."""
    md5 = hashlib.md5()  # modify if crash for large
    for chunk in filecnt.chunks():
        md5.update(chunk)
    md5sum = md5.hexdigest()
    anal_dir = os.path.join(str(settings.MEDIA_ROOT / 'upload'), md5sum + '/')
    if not os.path.exists(anal_dir):
        os.makedirs(anal_dir)
    with open(anal_dir + md5sum + typ, 'wb+') as destination:
        for chunk in filecnt.chunks():
            destination.write(chunk)
    return md5sum


class Scanning(object):

    def __init__(self, request):
        self.file = request.FILES['file']
        self.file_name = request.FILES['file'].name

    def scan_apk(self):
        """Android APK."""
        md5 = handle_uploaded_file(self.file, '.apk')
        app_dir = settings.MEDIA_ROOT / 'upload' / md5
        app_path = app_dir / (md5+'.apk')
        _apk = apk.APK(app_path)
        data = {
            'analyzer': 'static_analyzer',
            'status': 'success',
            'hash': md5,
            'scan_type': 'apk',
            'file_name': self.file_name,
            'app_name':_apk.get_app_name(),
            'packge_name':_apk.get_package(),
            'version_name':_apk.get_androidversion_name()
        }
        add_to_recent_scan(data)
        logger.info('执行Android APK的静态分析')
        return data

    def scan_zip(self):
        """Zipped Source."""
        md5 = handle_uploaded_file(self.file, '.zip')
        data = {
            'analyzer': 'static_analyzer',
            'status': 'success',
            'hash': md5,
            'scan_type': 'zip',
            'file_name': self.file_name,
        }
        add_to_recent_scan(data)
        logger.info('执行Android 源代码的静态分析')
        return data
