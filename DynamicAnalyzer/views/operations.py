# -*- coding: utf_8 -*-
"""动态分析时操作"""
import json
import logging
import os
import random
import re
import subprocess
import threading

from django.conf import settings
from django.http import HttpResponse
from django.views.decorators.http import require_http_methods

from DynamicAnalyzer.views.environment import (
    Environment,
)
from securityanalyzer.utils import (
    get_adb,
    get_device,
    is_md5,
    is_number,
)
from StaticAnalyzer.models import StaticAnalyzerAndroid

logger = logging.getLogger(__name__)


# Helpers

def get_package_name(checksum):
    """从数据库中返回包名"""
    try:
        static_android_db = StaticAnalyzerAndroid.objects.get(
            MD5=checksum)
        return static_android_db.PACKAGE_NAME
    except Exception:
        return None


def send_response(data):
    """返回JSON Response."""
    return HttpResponse(json.dumps(data),
                        content_type='application/json')


def is_attack_pattern(user_input):
    """检查攻击字段"""
    atk_pattern = re.compile(r';|\$\(|\|\||&&')
    stat = re.findall(atk_pattern, user_input)
    if stat:
        logger.error('检测到可能的RCE攻击')
    return stat


def strict_package_check(user_input):
    """包名检查"""
    pat = re.compile(r'^\w+\.*[\w\.\$]+$')
    resp = re.match(pat, user_input)
    if not resp:
        logger.error('请检查package或class名')
    return resp


def is_path_traversal(user_input):
    """检查路径遍历"""
    if (('../' in user_input)
        or ('%2e%2e' in user_input)
        or ('..' in user_input)
            or ('%252e' in user_input)):
        logger.error('检测到路径遍历攻击')
        return True
    return False


def invalid_params():
    """检查参数的标准返回样式"""
    msg = 'Invalid Parameters'
    logger.error(msg)
    data = {'status': 'failed', 'message': msg}
    return send_response(data)

# AJAX
@require_http_methods(['POST'])
def mobsfy(request):
    """初始Android动态分析"""
    logger.info('初始Android设备动态分析环境')
    data = {}
    try:
        identifier = request.POST['identifier']
        create_env = Environment(identifier)
        if not create_env.connect_n_mount():
            msg = 'Connection failed'
            data = {'status': 'failed', 'message': msg}
            return send_response(data)
        version = create_env.env_init()
        if not version:
            msg = 'Connection failed'
            data = {'status': 'failed', 'message': msg}
            return send_response(data)
        else:
            data = {'status': 'ok', 'android_version': version}
    except Exception as exp:
        logger.exception('Android instance failed')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data)

# AJAX
@require_http_methods(['POST'])
def execute_adb(request):
    """执行ADB命令."""
    data = {'status': 'ok', 'message': ''}
    cmd = request.POST['cmd']
    if cmd:
        args = [get_adb(),
                '-s',
                get_device()]
        try:
            proc = subprocess.Popen(args + cmd.split(' '),
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            stdout, stderr = proc.communicate()
        except Exception:
            logger.exception('Executing ADB Commands')
        if stdout or stderr:
            out = stdout or stderr
            out = out.decode('utf8', 'ignore')
        else:
            out = ''
        data = {'status': 'ok', 'message': out}
    return send_response(data)


# AJAX
@require_http_methods(['POST'])
def get_component(request):
    """获取Android组件"""
    data = {}
    try:
        env = Environment()
        comp = request.POST['component']
        bin_hash = request.POST['hash']
        if is_attack_pattern(comp) or not is_md5(bin_hash):
            return invalid_params()
        comp = env.android_component(bin_hash, comp)
        data = {'status': 'ok', 'message': comp}
    except Exception as exp:
        logger.exception('Getting Android Component')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data)


# AJAX
@require_http_methods(['POST'])
def take_screenshot(request):
    """Take Screenshot."""
    logger.info('Taking screenshot')
    data = {}
    try:
        env = Environment()
        bin_hash = request.POST['hash']
        if not is_md5(bin_hash):
            return invalid_params()
        data = {}
        rand_int = random.randint(1, 1000000)
        screen_dir = os.path.join(settings.MEDIA_ROOT / 'downloads',
                                  bin_hash + '/screenshots-apk/')
        if not os.path.exists(screen_dir):
            os.makedirs(screen_dir)
        outile = '{}screenshot-{}.png'.format(
            screen_dir,
            str(rand_int))
        env.screen_shot(outile)
        logger.info('Screenshot captured')
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('Taking screenshot')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data)


# AJAX
@require_http_methods(['POST'])
def screen_cast(request):
    """ScreenCast."""
    data = {}
    try:
        env = Environment()
        trd = threading.Thread(target=env.screen_stream)
        trd.daemon = True
        trd.start()
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('Screen streaming')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data)


# AJAX
@require_http_methods(['POST'])
def touch(request):
    """Sending Touch Events."""
    data = {}
    try:
        env = Environment()
        x_axis = request.POST['x']
        y_axis = request.POST['y']
        if not is_number(x_axis) and not is_number(y_axis):
            logger.error('位置参数必须是数字')
            return invalid_params()
        args = ['input',
                'tap',
                x_axis,
                y_axis]
        trd = threading.Thread(target=env.adb_command,
                               args=(args, True))
        trd.daemon = True
        trd.start()
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('Sending Touch Events')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data)



# AJAX
@require_http_methods(['POST'])
def mobsf_ca(request):
    """安装或移除mitm证书"""
    data = {}
    try:
        env = Environment()
        action = request.POST['action']
        if action == 'install':
            env.install_mitm_ca(action)
            data = {'status': 'ok', 'message': 'installed'}
        elif action == 'remove':
            env.install_mitm_ca(action)
            data = {'status': 'ok', 'message': 'removed'}
        else:
            data = {'status': 'failed',
                    'message': 'Action not supported'}
    except Exception as exp:
        logger.exception('mitm RootCA Handler')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data)
