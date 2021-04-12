# -*- coding: utf_8 -*-
"""Android Dynamic Analysis."""
import logging
import os
import time
from pathlib import Path

from shelljob import proc

from django.http import (HttpResponseRedirect,
                         StreamingHttpResponse)
from django.conf import settings
from django.shortcuts import render

from DynamicAnalyzer.views.environment import Environment
from DynamicAnalyzer.views.operations import (
    get_package_name,
    strict_package_check,
)
from DynamicAnalyzer.tools.webproxy import (
    start_httptools_ui,
    stop_httptools,
)
from securityanalyzer.utils import (
    get_config_loc,
    get_device,
    get_http_tools_url,
    get_proxy_ip,
    is_md5,
    print_n_send_error_response,
)
from StaticAnalyzer.models import StaticAnalyzerAndroid

logger = logging.getLogger(__name__)


def dynamic_analysis(request, api=False):
    """Android动态分析入口"""
    try:
        scan_apps = []
        apks = StaticAnalyzerAndroid.objects.filter(
            APP_TYPE='apk').order_by('-id')
        for apk in apks:
            temp_dict = {
                'MD5': apk.MD5,
                'APP_NAME': apk.APP_NAME,
                'VERSION_NAME': apk.VERSION_NAME,
                'FILE_NAME': apk.FILE_NAME,
                'PACKAGE_NAME': apk.PACKAGE_NAME,
            }
            scan_apps.append(temp_dict)
        try:
            #获取设备id
            identifier = get_device()
        except Exception:
            msg = ('Android设备运行了吗'
                   '找不到设备id'
                   '请重新启动设备再刷新此页面')
            return print_n_send_error_response(request, msg, api)
        proxy_ip = get_proxy_ip(identifier)
        context = {'apps': scan_apps,
                   'identifier': identifier,
                   'proxy_ip': proxy_ip,
                   'proxy_port': settings.PROXY_PORT,
                   'title': 'Dynamic Analysis',}
        template = 'dynamic_analysis/dynamic_analysis.html'
        return render(request, template, context)
    except Exception as exp:
        logger.exception('Dynamic Analysis')
        return print_n_send_error_response(request,
                                           exp,
                                           api)


def dynamic_analyzer(request, checksum, api=False):
    """Android Dynamic Analyzer Environment."""
    logger.info('创建动态分析环境')
    try:
        no_device = False
        if not is_md5(checksum):
            # 检查MD5值
            return print_n_send_error_response(
                request,
                'Invalid Parameters',
                api)
        package = get_package_name(checksum)
        if not package:
            return print_n_send_error_response(
                request,
                'Invalid Parameters',
                api)
        try:
            identifier = get_device()
        except Exception:
            no_device = True
        if no_device or not identifier:
            msg = ('Android设备运行了吗'
                   '找不到设备id'
                   '请重新启动设备再刷新此页面')
            return print_n_send_error_response(request, msg, api)
        env = Environment(identifier)
        if not env.connect_n_mount():
            msg = 'Cannot Connect to ' + identifier
            return print_n_send_error_response(request, msg, api)
        version = env.get_android_version()
        logger.info('Android Version identified as %s', version)
        if not env.is_init():
            msg = ('设备动态分析环境未被初始化或已经过时，正重新设置环境')
            logger.warning(msg)
            if not env.env_init():
                return print_n_send_error_response(
                    request,
                    '设备环境初始化失败',
                    api)
        # 分析之前清除旧数据
        env.dz_cleanup(checksum)
        # 配置代理
        env.configure_proxy(package, request)
        # Supported in Android 5+
        env.enable_adb_reverse_tcp(version)
        # 设置代理
        env.set_global_proxy(version)
        # 开启剪贴板监听
        env.start_clipmon()
        # 获取屏幕分辨率
        screen_width, screen_height = env.get_screen_res()
        apk_path = Path(settings.MEDIA_ROOT) / 'upload' / checksum / f'{checksum}.apk'
        # Install APK
        status, output = env.install_apk(apk_path.as_posix(), package)
        if not status:
            # Unset Proxy
            env.unset_global_proxy()
            msg = (f'安装APK失败 '
                   f'APK能安装在分析该设备上吗?\n{output}')
            return print_n_send_error_response(
                request,
                msg,
                api)
        logger.info('测试环境已经准备好了!')
        context = {'screen_witdth': screen_width,
                   'screen_height': screen_height,
                   'package': package,
                   'hash': checksum,
                   'android_version': version,
                   'title': '动态分析'}
        template = 'dynamic_analysis/android/dynamic_analyzer.html'
        return render(request, template, context)
    except Exception:
        logger.exception('Dynamic Analyzer')
        return print_n_send_error_response(
            request,
            'Dynamic Analysis Failed.',
            api)


def httptools_start(request):
    """Start httprools UI."""
    logger.info('Starting httptools Web UI')
    try:
        httptools_url = get_http_tools_url(request)
        stop_httptools(httptools_url)
        start_httptools_ui(settings.PROXY_PORT)
        time.sleep(3)
        logger.info('httptools UI started')
        if request.GET['project']:
            project = request.GET['project']
        else:
            project = ''
        url = f'{httptools_url}/dashboard/{project}'
        return HttpResponseRedirect(url)  # lgtm [py/reflective-xss]
    except Exception:
        logger.exception('Starting httptools Web UI')
        err = 'Error Starting httptools UI'
        return print_n_send_error_response(request, err)


def logcat(request, api=False):
    logger.info('Starting Logcat streaming')
    try:
        pkg = request.GET.get('package')
        if pkg:
            if not strict_package_check(pkg):
                return print_n_send_error_response(
                    request,
                    'Invalid package name',
                    api)
            template = 'dynamic_analysis/android/logcat.html'
            return render(request, template, {'package': pkg})
        if api:
            app_pkg = request.POST['package']
        else:
            app_pkg = request.GET.get('app_package')
        if app_pkg:
            if not strict_package_check(app_pkg):
                return print_n_send_error_response(
                    request,
                    'Invalid package name',
                    api)
            adb = os.environ['MOBSF_ADB']
            g = proc.Group()
            g.run([adb, 'logcat', app_pkg + ':V', '*:*'])

            def read_process():
                while g.is_pending():
                    lines = g.readlines()
                    for _, line in lines:
                        time.sleep(.01)
                        yield 'data:{}\n\n'.format(line)
            return StreamingHttpResponse(read_process(),
                                         content_type='text/event-stream')
        return print_n_send_error_response(
            request,
            'Invalid parameters',
            api)
    except Exception:
        logger.exception('Logcat Streaming')
        err = 'Error in Logcat streaming'
        return print_n_send_error_response(request, err, api)
