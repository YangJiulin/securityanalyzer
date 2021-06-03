"""Common Utils."""
import ast
import logging
import ntpath
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import stat
import sqlite3
import unicodedata
import zipfile
import psutil
import requests
from django.shortcuts import render
from . import settings

logger = logging.getLogger(__name__)
ADB_PATH = None


class Color(object):
    GREEN = '\033[92m'
    ORANGE = '\033[33m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'


def upstream_proxy(flaw_type):
    """Set upstream Proxy if needed."""
    if settings.UPSTREAM_PROXY_ENABLED:
        if not settings.UPSTREAM_PROXY_USERNAME:
            proxy_port = str(settings.UPSTREAM_PROXY_PORT)
            proxy_host = '{}://{}:{}'.format(
                settings.UPSTREAM_PROXY_TYPE,
                settings.UPSTREAM_PROXY_IP,
                proxy_port)
            proxies = {flaw_type: proxy_host}
        else:
            proxy_port = str(settings.UPSTREAM_PROXY_PORT)
            proxy_host = '{}://{}:{}@{}:{}'.format(
                settings.UPSTREAM_PROXY_TYPE,
                settings.UPSTREAM_PROXY_USERNAME,
                settings.UPSTREAM_PROXY_PASSWORD,
                settings.UPSTREAM_PROXY_IP,
                proxy_port)
            proxies = {flaw_type: proxy_host}
    else:
        proxies = {flaw_type: None}
    verify = bool(settings.UPSTREAM_PROXY_SSL_VERIFY)
    return proxies, verify



def find_java_binary():
    """Find Java."""
    # Respect user settings
    if platform.system() == 'Windows':
        jbin = 'java.exe'
    else:
        jbin = 'java'
    if is_dir_exists(settings.JAVA_DIRECTORY) and len(settings.JAVA_DIRECTORY) > 0:
        if settings.JAVA_DIRECTORY.endswith('/'):
            return settings.JAVA_DIRECTORY + jbin
        elif settings.JAVA_DIRECTORY.endswith('\\'):
            return settings.JAVA_DIRECTORY + jbin
        else:
            return settings.JAVA_DIRECTORY + '/' + jbin
    if os.getenv('JAVA_HOME'):
        java = os.path.join(
            os.getenv('JAVA_HOME'),
            'bin',
            jbin)
        if is_file_exists(java):
            return java
    return 'java'


def find_scala_binary():
    """Find scala."""
    # Respect user settings
    if platform.system() == 'Windows':
        sbin = 'scala.exe'
    else:
        sbin = 'scala'
    if is_dir_exists(settings.SCALA_DIRECTORY) and len(settings.SCALA_DIRECTORY) > 0:
        if settings.SCALA_DIRECTORY.endswith('/'):
            return settings.SCALA_DIRECTORY + sbin
        elif settings.SCALA_DIRECTORY.endswith('\\'):
            return settings.SCALA_DIRECTORY + sbin
        else:
            return settings.SCALA_DIRECTORY + '/' + sbin
    if os.getenv('SCALA_HOME'):
        scala = os.path.join(
            os.getenv('SCALA_HOME'),
            'bin',
            sbin)
        if is_file_exists(scala):
            return scala
    return 'scala'


def print_n_send_error_response(request,
                                msg,
                                exp='描述'):
    """打印错误日志"""
    logger.error(msg)
    context = {
            'title': 'Error',
            'exp': exp,
            'doc': msg,
        }
    template = 'general/error.html'
    return render(request, template, context, status=500)


def filename_from_path(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)


def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        pass
    try:
        unicodedata.numeric(s)
        return True
    except (TypeError, ValueError):
        pass
    return False


def python_list(value):
    """字符类型转换"""
    if not value:
        value = []
    if isinstance(value, list):
        return value
    return ast.literal_eval(value)


def python_dict(value):
    """字符类型转换"""
    if not value:
        value = {}
    if isinstance(value, dict):
        return value
    return ast.literal_eval(value)


def is_internet_available():
    try:
        proxies, verify = upstream_proxy('https')
    except Exception:
        logger.exception('Setting upstream proxy')
    try:
        requests.get(settings.GOOGLE,
                     timeout=5,
                     proxies=proxies,
                     verify=verify)
        return True
    except Exception:
        try:
            requests.get(settings.BAIDU,
                         timeout=5,
                         proxies=proxies,
                         verify=verify)
            return True
        except Exception:
            return False


def is_file_exists(file_path):
    if os.path.isfile(file_path):
        return True
    # 针对PATH中的可执行文件
    # inside settings.py
    if shutil.which(file_path):
        return True
    else:
        return False


def is_dir_exists(dir_path):
    if os.path.isdir(dir_path):
        return True
    else:
        return False


def find_process_by(name):
    """通过名字返回可执行文件路径"""
    proc = set()
    for p in psutil.process_iter(attrs=['name']):
        if (name == p.info['name']):
            proc.add(p.exe())
    return proc


def get_device():
    """Get Device."""
    out = subprocess.check_output([get_adb(), 'devices']).splitlines()
    if len(out) > 2:
        dev_id = out[1].decode('utf-8').split('\t')[0]
        return dev_id
    logger.error('启动安卓设备了吗?\n'
                 '找不到设备id\n')


def get_adb():
    """Get ADB binary path."""
    try:
        adb_loc = None
        global ADB_PATH
        if (len(settings.ADB_BINARY) > 0
                and is_file_exists(settings.ADB_BINARY)):
            ADB_PATH = settings.ADB_BINARY
            return ADB_PATH
        if ADB_PATH:
            return ADB_PATH
        if platform.system() == 'Windows':
            adb_loc = find_process_by('adb.exe')
        else:
            adb_loc = find_process_by('adb')
        if len(adb_loc) > 1:
            logger.warning('发现多个adb文件')
            logger.warning(adb_loc)
        if adb_loc:
            ADB_PATH = adb_loc.pop()
            return ADB_PATH
    except Exception:
        if not adb_loc:
            logger.warning('Cannot find adb!')
        logger.exception('Getting ADB Location')
    finally:
        if ADB_PATH:
            os.environ['ADB'] = ADB_PATH
        else:
            os.environ['ADB'] = 'adb'
            logger.warning('动态分析相关功能不起作用')
    return 'adb'


def check_basic_env():
    """Check if we have basic env to run.""" 
    logger.info('环境检查')
    try:
        import lxml  # noqa F401
    except ImportError:
        logger.exception('lxml is not installed!')
        os.kill(os.getpid(), signal.SIGTERM)
    if not is_file_exists(find_java_binary()):
        logger.error(
            'JDK 不可用。 '
            '设置环境变量JAVA_HOME或者JAVA_DIRECTORY'
            '%s')
        logger.info('当前配置: '
                    'JAVA_DIRECTORY=%s', 'settings.JAVA_DIRECTORY')
        logger.info('配置示例:'
                    '\nJAVA_DIRECTORY = "C:/Program Files/'
                    'Java/jdk1.7.0_17/bin/"'
                    '\nJAVA_DIRECTORY = "/usr/bin/"')
        os.kill(os.getpid(), signal.SIGTERM)
    if not is_file_exists(find_scala_binary()):
        logger.error(
            'SCALA 不可用。 '
            '设置环境变量SCALA_HOME或者SCALA_DIRECTORY'
            '%s')
        logger.info('当前配置: '
                    'SCALA_DIRECTORY=%s', 'settings.SCALA_DIRECTORY')
        logger.info('配置示例:'
                    '\nSCALA_DIRECTORY = "C:/Program Files/'
                    'Scala/scala/bin/"'
                    '\nSCALA_DIRECTORY = "/usr/bin/"')
        os.kill(os.getpid(), signal.SIGTERM)
    get_adb()


def read_sqlite(sqlite_file):
    """Sqlite Dump - Readable Text."""
    logger.info('Reading SQLite db')
    table_dict = {}
    try:
        con = sqlite3.connect(sqlite_file)
        cur = con.cursor()
        cur.execute('SELECT name FROM sqlite_master WHERE type=\'table\';')
        tables = cur.fetchall()
        for table in tables:
            table_dict[table[0]] = {'head': [], 'data': []}
            cur.execute('PRAGMA table_info(\'%s\')' % table)
            rows = cur.fetchall()
            for sq_row in rows:
                table_dict[table[0]]['head'].append(sq_row[1])
            cur.execute('SELECT * FROM \'%s\'' % table)
            rows = cur.fetchall()
            for sq_row in rows:
                tmp_row = []
                for each_row in sq_row:
                    tmp_row.append(str(each_row))
                table_dict[table[0]]['data'].append(tmp_row)
    except Exception:
        logger.exception('Reading SQLite db')
    return table_dict


def is_pipe_or_link(path):
    """Check for named pipe."""
    return os.path.islink(path) or stat.S_ISFIFO(os.stat(path).st_mode)


def get_network():
    """Get Network IPs."""
    ips = []
    try:
        for det in psutil.net_if_addrs().values():
            ips.append(det[0].address)
    except Exception:
        logger.exception('获取网络接口失败')
    return ips


def get_proxy_ip(identifier):
    """Get Proxy IP."""
    proxy_ip = None
    try:
        if not identifier:
            return proxy_ip
        ips = get_network()
        if ':' not in identifier or not ips:
            return proxy_ip
        device_ip = identifier.split(':', 1)[0]
        ip_range = device_ip.rsplit('.', 1)[0]
        guess_ip = ip_range + '.1'
        if guess_ip in ips:
            return guess_ip
        for ip_addr in ips:
            to_check = ip_addr.rsplit('.', 1)[0]
            if to_check == ip_range:
                return ip_addr
    except Exception:
        logger.error('Error getting Proxy IP')
    return proxy_ip


def is_safe_path(safe_root, check_path):
    """Detect Path Traversal."""
    safe_root = os.path.realpath(os.path.normpath(safe_root))
    check_path = os.path.realpath(os.path.normpath(check_path))
    return os.path.commonprefix([check_path, safe_root]) == safe_root


def file_size(app_path):
    """Return the size of the file."""
    return round(float(os.path.getsize(app_path)) / (1024 * 1024), 2)


def is_md5(user_input):
    """Check if string is valid MD5."""
    stat = re.match(r'^[0-9a-f]{32}$', user_input)
    if not stat:
        logger.error('Invalid scan hash')
    return stat

def get_http_tools_url(req):
    """从request中获取httptools URL."""
    scheme = req.scheme
    ip = req.get_host().split(':')[0]
    return f'{scheme}://{ip}:9090'


def can_run_flow():
    available = psutil.virtual_memory().available // 2 ** 20 #MB
    if available <= 2000:
        return False
    return True

def unzip(app_path, ext_path):
    logger.info('Unzipping')
    try:
        files = []
        with zipfile.ZipFile(app_path, 'r') as zipptr:
            for fileinfo in zipptr.infolist():
                filename = fileinfo.filename
                if not isinstance(filename, str):
                    filename = str(
                        filename, encoding='utf-8', errors='replace')
                files.append(filename)
                zipptr.extract(filename, ext_path)
        return files
    except Exception:
        logger.exception('Unzipping Error')
        if platform.system() == 'Windows':
            logger.info('Not yet Implemented.')
        else:
            logger.info('Using the Default OS Unzip Utility.')
            try:
                unzip_b = shutil.which('unzip')
                subprocess.call(
                    [unzip_b, '-o', '-q', app_path, '-d', ext_path])
                dat = subprocess.check_output([unzip_b, '-qq', '-l', app_path])
                dat = dat.decode('utf-8').split('\n')
                files_det = ['Length   Date   Time   Name']
                files_det = files_det + dat
                return files_det
            except Exception:
                logger.exception('Unzipping Error')