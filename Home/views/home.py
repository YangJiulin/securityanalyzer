#  -*- coding: utf_8 -*-
# """Upload and Home Routes."""
from StaticAnalyzer.models import RecentScansDB, StaticAnalyzerAndroid
import json
import logging
import os
import re
from securityanalyzer.utils import is_dir_exists, is_file_exists, print_n_send_error_response
import shutil
from wsgiref.util import FileWrapper

from django.conf import settings
from django.core.paginator import Paginator
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.template.defaulttags import register

from Home.forms import UploadFileForm,FormUtil
from Home.views.helpers import FileType
from Home.views.scanning import Scanning

LINUX_PLATFORM = ['Darwin', 'Linux']
HTTP_BAD_REQUEST = 400
logger = logging.getLogger(__name__)


@register.filter
def key(d, key_name):
    """在模板中通过key获取字典元素"""
    return d.get(key_name)


def index(request):
    """主页"""
    mimes = (settings.APK_MIME
             + settings.ZIP_MIME)
    context = {
        'mimes': mimes,
    }
    template = 'general/home.html'
    return render(request, template, context)


def live_log(request):
    try:
        log_file = settings.BASE_DIR/'logs'/'debug.log'
        data = {}
        if not is_file_exists(log_file):
            data = {
                'status': 'failed',
                'message': 'Data does not exist.'}
            return HttpResponse(json.dumps(data),
                            content_type='application/json; charset=utf-8')
        with open(log_file, 'r',encoding='utf8',errors='ignore') as flip:
            data = {'data': flip.read()}
        return HttpResponse(json.dumps(data),
                            content_type='application/json; charset=utf-8')
    except Exception:
        logger.exception('log 实时监控')
        err = 'Error in log streaming'
        return print_n_send_error_response(request, err)

class Upload(object):
    """根据上传文件的不同类型处理文件"""

    def __init__(self, request):
        self.request = request
        self.form = UploadFileForm(request.POST, request.FILES)
        self.file_type = None
        self.file = None

    @staticmethod
    def as_view(request):
        upload = Upload(request)
        return upload.upload_html()

    def resp_json(self, data):
        resp = HttpResponse(json.dumps(data),
                            content_type='application/json; charset=utf-8')
        resp['Access-Control-Allow-Origin'] = '*'
        return resp

    def upload_html(self):
        request = self.request
        response_data = {
            'description': '',
            'status': 'error',
        }
        if request.method != 'POST':
            msg = 'Method not Supported!'
            logger.error(msg)
            response_data['description'] = msg
            return self.resp_json(response_data)

        if not self.form.is_valid():
            msg = 'Invalid Form Data!'
            logger.error(msg)
            response_data['description'] = msg
            return self.resp_json(response_data)

        self.file = request.FILES['file']
        self.file_type = FileType(self.file)
        if not self.file_type.is_allow_file():
            msg = 'File format not Supported!'
            logger.error(msg)
            response_data['description'] = msg
            return self.resp_json(response_data)

        response_data = self.upload()
        return self.resp_json(response_data)

    def upload(self):
        request = self.request
        scanning = Scanning(request)
        content_type = self.file.content_type
        file_name = self.file.name
        logger.info('MIME Type: %s FILE: %s', content_type, file_name)
        if self.file_type.is_apk():
            return scanning.scan_apk()
        elif self.file_type.is_zip():
            return scanning.scan_zip()



def error(request):
    """Error Route."""
    context = {
        'title': 'Error',
    }
    template = 'general/error.html'
    return render(request, template, context)


def zip_format(request):
    """Zip Format Message Route."""
    context = {
        'title': 'Zipped Source Instruction',
    }
    template = 'general/zip.html'
    return render(request, template, context)


def not_found(request):
    """Not Found Route."""
    context = {
        'title': 'Not Found',
    }
    template = 'general/not_found.html'
    return render(request, template, context)


def recent_scans(request):
    """Show Recent Scans Route."""
    entries = RecentScansDB.objects.all().order_by('-TIMESTAMP').values()
    context = {
        'title': 'Recent Scans',
        'entries': entries,
    }
    template = 'general/recent.html'
    return render(request, template, context)

def search(request):
    """Search Scan by MD5 Route."""
    md5 = request.GET['md5']
    if re.match('[0-9a-f]{32}', md5):
        db_obj = RecentScansDB.objects.filter(MD5=md5)
        if db_obj.exists():
            e = db_obj[0]
            url = (f'/{e.ANALYZER }/?name={e.FILE_NAME}&'
                   f'checksum={e.MD5}&type={e.SCAN_TYPE}')
            return HttpResponseRedirect(url)
        else:
            return HttpResponseRedirect('/not_found/')
    return print_n_send_error_response(request, '检查输入hash值')


def download(request):
    """Download Handler"""
    msg = 'Error Downloading File '
    if request.method == 'GET':
        allowed_exts = settings.ALLOWED_EXTENSIONS
        filename = request.path.replace('/download/', '', 1)
        # Security Checks
        if '../' in filename:
            msg = '发现路径遍历攻击'
            return print_n_send_error_response(request, msg)
        ext = os.path.splitext(filename)[1]
        if ext in allowed_exts:
            dwd_file = os.path.join(settings.DWD_DIR, filename)
            if os.path.isfile(dwd_file):
                wrapper = FileWrapper(open(dwd_file, 'rb'))
                response = HttpResponse(
                    wrapper, content_type=allowed_exts[ext])
                response['Content-Length'] = os.path.getsize(dwd_file)
                return response
    if ('screen/screen.png' not in filename):
        msg += filename
        return print_n_send_error_response(request, msg)
    return HttpResponse('')


def delete_scan(request):
    try:
        if request.method == 'POST':
            md5_hash = request.POST['md5']
            data = {'deleted': 'scan hash not found'}
            if re.match('[0-9a-f]{32}', md5_hash):
                # Delete DB Entries
                scan = RecentScansDB.objects.filter(MD5=md5_hash)
                if scan.exists():
                    RecentScansDB.objects.filter(MD5=md5_hash).delete()
                    StaticAnalyzerAndroid.objects.filter(MD5=md5_hash).delete()
                    # Delete Upload Dir Contents
                    app_upload_dir = os.path.join(settings.MEDIA_ROOT / 'upload', md5_hash)
                    if is_dir_exists(app_upload_dir):
                        shutil.rmtree(app_upload_dir)
                    # Delete Download Dir Contents
                    dw_dir = settings.DWD_DIR
                    for item in os.listdir(dw_dir):
                        item_path = os.path.join(dw_dir, item)
                        valid_item = item.startswith(md5_hash)
                        # Delete all related files
                        if is_file_exists(item_path) and valid_item:
                            os.remove(item_path)
                        # Delete related directories
                        if is_dir_exists(item_path) and valid_item:
                            shutil.rmtree(item_path)
                    data = {'deleted': 'yes'}
            ctype = 'application/json; charset=utf-8'
            return HttpResponse(json.dumps(data), content_type=ctype)
    except Exception as exp:
        msg = str(exp)
        exp_doc = exp.__doc__
        return print_n_send_error_response(request, msg, False, exp_doc)

