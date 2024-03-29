# -*- coding: utf_8 -*-
"""Available Actions."""
from DynamicAnalyzer.tools.webproxy import stop_httptools
import logging
import os
from time import time

from django.conf import settings
from django.views.decorators.http import require_http_methods

from DynamicAnalyzer.views.operations import (
    get_package_name,
    invalid_params,
    send_response,
)
from DynamicAnalyzer.views.environment import (
    Environment,
)
from securityanalyzer.utils import (
    is_md5,
    is_number,
    python_list,
)
from StaticAnalyzer.models import StaticAnalyzerAndroid

logger = logging.getLogger(__name__)

# AJAX


@require_http_methods(['POST'])
def activity_tester(request):
    """Exported & non exported activity Tester."""
    data = {}
    try:
        env = Environment()
        test = request.POST['test']
        md5_hash = request.POST['hash']
        if not is_md5(md5_hash):
            return invalid_params()
        app_dir = os.path.join(settings.MEDIA_ROOT / 'upload', md5_hash + '/')
        screen_dir = os.path.join(app_dir, 'screenshots-apk/')
        if not os.path.exists(screen_dir):
            os.makedirs(screen_dir)
        static_android_db = StaticAnalyzerAndroid.objects.get(
            MD5=md5_hash)
        package = static_android_db.PACKAGE_NAME
        iden = ''
        if test == 'exported':
            iden = 'Exported '
            logger.info('Exported activity tester')
            activities = python_list(static_android_db.EXPORTED_ACTIVITIES)
        logger.info('Fetching %sactivities for %s', iden, package)
        if not activities:
            msg = 'No {}Activites found'.format(iden)
            logger.info(msg)
            data = {'status': 'failed',
                    'message': msg}
            return send_response(data)
        act_no = 0
        logger.info('Starting %sActivity Tester...', iden)
        logger.info('%s %sActivities Identified',
                    str(len(activities)), iden)
        for activity in activities:
            act_no += 1
            logger.info(
                'Launching %sActivity - %s. %s',
                iden,
                str(act_no),
                activity)
            if test == 'exported':
                file_iden = 'expact'
            outfile = ('{}{}-{}.png'.format(
                screen_dir,
                file_iden,
                act_no))
            env.launch_n_capture(package, activity, outfile)
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('%sActivity tester', iden)
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data)

# AJAX


@require_http_methods(['POST'])
def download_data(request):
    """从设备下载应用文件."""
    logger.info('Downloading app data')
    data = {}
    try:
        env = Environment()
        md5_hash = request.POST['hash']
        if not is_md5(md5_hash):
            return invalid_params()
        package = get_package_name(md5_hash)
        if not package:
            data = {'status': 'failed',
                    'message': 'App details not found in database'}
            return send_response(data)
        apk_dir = os.path.join(settings.MEDIA_ROOT / 'upload', md5_hash + '/')
        files_loc = '/data/local/'
        logger.info('获取并压缩APP应用数据')
        env.adb_command(['tar', '-cvf', files_loc + package + '.tar',
                         '/data/data/' + package + '/'], True)
        logger.info('下载存档')
        env.adb_command(['pull', files_loc + package + '.tar',
                         apk_dir + package + '.tar'])
        logger.info('Stopping ADB server')
        env.adb_command(['kill-server'])
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('Downloading application data')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data)

# AJAX


@require_http_methods(['POST'])
def collect_logs(request):
    """Collecting Data and Cleanup."""
    logger.info('Collecting Data and Cleaning Up')
    data = {}
    try:
        env = Environment()
        md5_hash = request.POST['hash']
        if not is_md5(md5_hash):
            return invalid_params()
        package = get_package_name(md5_hash)
        if not package:
            data = {'status': 'failed',
                    'message': 'App details not found in database'}
            return send_response(data)
        apk_dir = os.path.join(settings.MEDIA_ROOT / 'upload', md5_hash + '/')
        lout = os.path.join(apk_dir, 'logcat.txt')
        dout = os.path.join(apk_dir, 'dump.txt')
        logger.info('Downloading logcat logs')
        logcat = env.adb_command(['logcat',
                                  '-d',
                                  package + ':V',
                                  '*:*'])
        with open(lout, 'wb') as flip:
            flip.write(logcat)
        logger.info('Downloading dumpsys logs')
        dumpsys = env.adb_command(['dumpsys'], True)
        with open(dout, 'wb') as flip:
            flip.write(dumpsys)
        env.adb_command(['am', 'force-stop', package], True)
        logger.info('Stopping app')
        # Unset Global Proxy
        env.unset_global_proxy()
        pid = request.POST['pid']
        if is_number(pid):
            stop_httptools(pid)
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('Data Collection & Clean Up failed')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data)
