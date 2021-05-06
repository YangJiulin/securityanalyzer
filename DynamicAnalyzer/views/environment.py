# -*- coding: utf_8 -*-
"""动态分析环境"""
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from hashlib import md5

from django.conf import settings

from OpenSSL import crypto

from DynamicAnalyzer.tools.webproxy import (
    get_ca_file,
    start_proxy,
)
from DynamicAnalyzer.views import frida_server_download as fserver
from securityanalyzer.utils import (
    get_adb,
    get_device,
    is_file_exists,
    python_list,
)
from StaticAnalyzer.models import StaticAnalyzerAndroid

logger = logging.getLogger(__name__)
ANDROID_API_SUPPORTED = 29
FRIDA_VERSION = '14.2.14'


class Environment:

    def __init__(self, identifier=None):
        if identifier:
            self.identifier = identifier
        else:
            self.identifier = get_device()
        self.tools_dir = settings.TOOLS_DIR.as_posix()
        self.frida_str = f'Frida-{FRIDA_VERSION}'.encode('utf-8')

    def wait(self, sec):
        """Wait in Seconds."""
        logger.info('Waiting for %s seconds...', str(sec))
        time.sleep(sec)

    def check_connect_error(self, output):
        """检查是否连接失败"""
        if b'unable to connect' in output or b'failed to connect' in output:
            logger.error('%s', output.decode('utf-8').replace('\n', ''))
            return False
        return True

    def run_subprocess_verify_output(self, command):
        """执行命令并验证结果"""
        out = subprocess.check_output(command)
        self.wait(2)
        return self.check_connect_error(out)

    def connect_n_mount(self):
        """测试连接"""
        self.adb_command(['kill-server'])
        self.adb_command(['start-server'])
        logger.info('ADB 重启')
        self.wait(2)
        logger.info('连接到Android设备 %s', self.identifier)
        if not self.run_subprocess_verify_output([get_adb(),
                                                 'connect',
                                                  self.identifier]):
            return False
        logger.info('以root方式重启 ADB Daemon ')
        if not self.run_subprocess_verify_output([get_adb(),
                                                  '-s',
                                                  self.identifier,
                                                  'root']):
            return False
        logger.info('重新连接Android设备')
        # connect again with root adb
        if not self.run_subprocess_verify_output([get_adb(),
                                                  'connect',
                                                  self.identifier]):
            return False
        logger.info('Remounting')
        # 获取/system分区读写权限，前提是设备已root
        self.adb_command(['remount'])
        logger.info('检查设备')
        if not self.system_check():
            return False
        return True

    def is_package_installed(self, package, extra):
        """检查测试软件是否安装"""
        #extra声明安装状态
        success = '\nSuccess' in extra
        out = self.adb_command(['pm', 'list', 'packages'], True)
        pkg = f'{package}'.encode('utf-8')
        pkg_fmts = [pkg + b'\n', pkg + b'\r\n', pkg + b'\r\r\n']
        if any(pkg in out for pkg in pkg_fmts):
            # Windows uses \r\n and \r\r\n
            return True
        if success:
            # Fallback check
            return True
        return False

    def install_apk(self, apk_path, package) -> bool: 
        """安装APK并验证安装结果"""
        if self.is_package_installed(package, ''):
            logger.info('卸载已安装apk')
            # Remove existing installation'
            self.adb_command(['uninstall', package], False, True)
        # 关闭adb安装确认
        self.adb_command([
            'settings',
            'put',
            'global',
            'verifier_verify_adb_installs',
            '0',
        ], True)
        logger.info('Installing APK')
        # Install APK
        out = self.adb_command([
            'install',
            '-r',
            '-t',
            '-d',
            apk_path], False, True)
        if not out:
            return False, 'adb install failed'
        out = out.decode('utf-8', 'ignore')
        # Verify Installation
        return self.is_package_installed(package, out), out

    def adb_command(self, cmd_list, shell=False, silent=False):
        """ADB Command wrapper."""
        args = [get_adb(),
                '-s',
                self.identifier]
        if shell:
            args += ['shell']
        args += cmd_list
        try:
            result = subprocess.check_output(
                args,
                stderr=subprocess.STDOUT)
            return result
        except Exception:
            if not silent:
                logger.exception('Error Running ADB Command')
            return None

    def dz_cleanup(self, bin_hash):
        """在动态分析前clean"""
        # Delete ScreenStream Cache
        screen_file = os.path.join(settings.SCREEN_DIR, 'screen.png')
        if os.path.exists(screen_file):
            os.remove(screen_file)
        # 删除Screenshot Dir里的文件
        screen_dir = os.path.join(
            settings.MEDIA_ROOT / 'downloads', bin_hash + '/screenshots-apk/')
        if os.path.isdir(screen_dir):
            shutil.rmtree(screen_dir)
        else:
            os.makedirs(screen_dir)

    def configure_proxy(self, request):
        """HTTPS Proxy."""
        self.install_mitm_ca('install')
        proxy_port = settings.PROXY_PORT
        logger.info('Starting HTTPs Proxy on %s', proxy_port)
        pid = start_proxy(proxy_port)
        return pid

    def install_mitm_ca(self, action):
        """安装或移除mitm证书"""
        mitm_ca = get_ca_file()
        ca_file = None
        if is_file_exists(mitm_ca):
            ca_construct = '{}.0'
            pem = open(mitm_ca, 'rb')
            ca_obj = crypto.load_certificate(crypto.FILETYPE_PEM, pem.read())
            md = md5(ca_obj.get_subject().der()).digest()
            ret = (md[0] | (md[1] << 8) | (md[2] << 16) | md[3] << 24)
            ca_file_hash = hex(ret).lstrip('0x')
            ca_file = os.path.join('/system/etc/security/cacerts/',
                                   ca_construct.format(ca_file_hash))
            pem.close()
        else:
            logger.warning('mitmproxy root CA 目前还未生成')
            return
        if action == 'install':
            logger.info('安装 mitm RootCA')
            self.adb_command(['push',
                              mitm_ca,
                              ca_file])
            self.adb_command(['chmod',
                              '644',
                              ca_file], True)
        elif action == 'remove':
            logger.info('移除 mitm RootCA')
            self.adb_command(['rm',
                              ca_file], True)
        # with a high timeout afterwards

    def set_global_proxy(self):
        """给设备设置全局代理"""
        # Android 4.4+ supported
        proxy_ip = None
        proxy_port = settings.PROXY_PORT
        proxy_ip = settings.PROXY_IP
        if proxy_ip:
            logger.info('给Android设备设置全局代理')
            self.adb_command(
                ['settings',
                 'put',
                 'global',
                 'http_proxy',
                 '{}:{}'.format(proxy_ip, proxy_port)], True)

    def unset_global_proxy(self):
        """取消设备的全局代理"""
        logger.info('删除Android设备的全局代理')
        self.adb_command(
            ['settings',
             'delete',
             'global',
             'http_proxy'], True)
        self.adb_command(
            ['settings',
             'delete',
             'global',
             'global_http_proxy_host'], True)
        self.adb_command(
            ['settings',
             'delete',
             'global',
             'global_http_proxy_port'], True)
        self.adb_command(
            ['settings',
             'put',
             'global',
             'http_proxy',
             ':0'], True)

    def enable_adb_reverse_tcp(self, version):
        """
        反向映射 将Android设备端口映射到远程端口
        # 反向映射端口连接(DEVICE —> PC)
        adb reverse (remote) (local)
        adb reverse tcp:7000 tcp:5000
        """
        # Androd 5+ supported
        proxy_port = settings.PROXY_PORT
        logger.info('Enabling ADB Reverse TCP on %s', proxy_port)
        tcp = 'tcp:{}'.format(proxy_port)
        try:
            proc = subprocess.Popen([get_adb(),
                                     '-s', self.identifier,
                                     'reverse', tcp, tcp],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            _, stderr = proc.communicate()
            if b'error: closed' in stderr:
                logger.warning('ADB Reverse TCP works only on'
                               ' Android 5.0 and above. Please '
                               'configure a reachable IP Address'
                               ' in Android proxy settings.')
            elif stderr:
                logger.error(stderr.decode('utf-8').replace('\n', ''))
        except Exception:
            logger.exception('Enabling ADB Reverse TCP')


    def get_screen_res(self):
        """获取Android设备的屏幕分辨率。"""
        logger.info('获取屏幕分辨率')
        try:
            resp = self.adb_command(['dumpsys', 'window'], True)
            scn_rgx = re.compile(r'mUnrestrictedScreen=\(0,0\) .*')
            scn_rgx2 = re.compile(r'mUnrestricted=\[0,0\]\[.*\]')
            match = scn_rgx.search(resp.decode('utf-8'))
            if match:
                screen_res = match.group().split(' ')[1]
                width, height = screen_res.split('x', 1)
                return width, height
            match = scn_rgx2.search(resp.decode('utf-8'))
            if match:
                res = match.group().split('][')[1].replace(']', '')
                width, height = res.split(',', 1)
                return width, height
            else:
                logger.error('获取屏幕分辨率时出错')
        except Exception:
            logger.exception('获取屏幕分辨率')
        return '1440', '2560'

    def screen_shot(self, outfile):
        """截图"""
        self.adb_command(['screencap',
                          '-p',
                          '/data/local/screen.png'], True)
        self.adb_command(['pull',
                          '/data/local/screen.png',
                          outfile])

    def screen_stream(self):
        """Screen Stream."""
        self.adb_command(['screencap',
                          '-p',
                          '/data/local/stream.png'],
                         True)
        self.adb_command(['pull',
                          '/data/local/stream.png',
                          str(settings.SCREEN_DIR / 'screen.png')])

    def android_component(self, bin_hash, comp):
        """获取apk组件信息"""
        anddb = StaticAnalyzerAndroid.objects.get(MD5=bin_hash)
        resp = []
        if comp == 'activities':
            resp = python_list(anddb.ACTIVITIES)
        elif comp == 'receivers':
            resp = python_list(anddb.RECEIVERS)
        elif comp == 'providers':
            resp = python_list(anddb.PROVIDERS)
        elif comp == 'services':
            resp = python_list(anddb.SERVICES)
        elif comp == 'libraries':
            resp = python_list(anddb.LIBRARIES)
        elif comp == 'exported_activities':
            resp = python_list(anddb.EXPORTED_ACTIVITIES)
        return '\n'.join(resp)


    def get_android_version(self):
        """Get Android version."""
        out = self.adb_command(['getprop',
                                'ro.build.version.release'], True)
        and_version = out.decode('utf-8').rstrip()
        if and_version.count('.') > 1:
            and_version = and_version.rsplit('.', 1)[0]
        if and_version.count('.') > 1:
            and_version = and_version.split('.', 1)[0]
        return float(and_version)

    def get_android_arch(self):
        """获取Android设备架构"""
        out = self.adb_command([
            'getprop',
            'ro.product.cpu.abi'], True)
        return out.decode('utf-8').rstrip()

    def system_check(self):
        """检查 /system 分区是否可写。"""
        try:
            err_msg = ('设备 /system 分区不可写。 '
                       '不能用于动态分析。')
            proc = subprocess.Popen([get_adb(),
                                     '-s', self.identifier,
                                     'shell',
                                     'touch',
                                     '/system/test'],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            _, stderr = proc.communicate()
            if b'Read-only' in stderr:
                logger.error(err_msg)
                logger.info('如果是AVD，请用命令行以可写的方式启动')
                # return False
        except Exception:
            logger.error(err_msg)
            return False
        return True

    def launch_n_capture(self, package, activity, outfile):
        """启动并捕获Activity图片"""
        self.adb_command(['am',
                          'start',
                          '-n',
                          package + '/' + activity], True)
        self.wait(5)
        self.screen_shot(outfile)
        logger.info('Activity截屏已保存')
        logger.info('停止APP')
        self.adb_command(['am', 'force-stop', package], True)

    def is_init(self):
        """检查设备是否已经初始化过环境"""
        logger.info('设备环境检查')
        agent_file = '.security-f'
        agent_str = self.frida_str
        try:
            out = subprocess.check_output(
                [get_adb(),
                 '-s', self.identifier,
                 'shell',
                 'cat',
                 '/system/' + agent_file])
            if agent_str not in out:
                return False
        except Exception:
            return False
        return True

    def env_init(self):
        """初始化环境"""
        version = self.get_android_version()
        logger.info('Android版本为 %s', version)
        try:
            #安装启动frida
            self.frida_setup()
            #安装设置代理
            self.mobsf_agents_setup()
            logger.info('设备环境初始化成功')
            return version
        except Exception:
            logger.exception('设备环境初始化失败')
            return False

    def mobsf_agents_setup(self):
        """安装设置代理"""
        # Install MITM RootCA
        self.install_mitm_ca('install')
        agent_file = '.security-f'
        agent_str = self.frida_str
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(agent_str)
        f.close()
        self.adb_command(['push', f.name, '/system/' + agent_file])
        os.unlink(f.name)


    def frida_setup(self):
        """Setup Frida."""
        frida_arch = None
        arch = self.get_android_arch()
        logger.info('Android系统架构为 %s', arch)
        if arch in ['armeabi-v7a', 'armeabi']:
            frida_arch = 'arm'
        elif arch == 'arm64-v8a':
            frida_arch = 'arm64'
        elif arch == 'x86':
            frida_arch = 'x86'
        elif arch == 'x86_64':
            frida_arch = 'x86_64'
        else:
            logger.error('确保有Android设备连接')
            return
        frida_bin = f'frida-server-{FRIDA_VERSION}-android-{frida_arch}'
        stat = fserver.update_frida_server(frida_arch, FRIDA_VERSION)
        if not stat:
            msg = ('下载frida-server失败。你需要下载到'
                   f' {frida_bin} in {settings.DWD_DIR} for '
                   '使动态分析能进行')
            logger.error(msg)
            return
        frida_path = os.path.join(settings.DWD_DIR, frida_bin)
        logger.info('复制 frida server %s 到Android设备', frida_arch)
        self.adb_command(['push', frida_path, '/system/fd_server'])
        self.adb_command(['chmod', '755', '/system/fd_server'], True)

    def run_frida_server(self):
        """Start Frida Server."""
        check = self.adb_command(['ps'], True)
        if b'fd_server' in check:
            logger.info('Frida Server正在运行中')
            return

        def start_frida():
            fnull = open(os.devnull, 'w')
            argz = [get_adb(),
                    '-s',
                    self.identifier,
                    'shell',
                    '/system/fd_server']
            subprocess.call(argz, stdout=fnull, stderr=subprocess.STDOUT)
        trd = threading.Thread(target=start_frida)
        trd.daemon = True
        trd.start()
        logger.info('启动 Frida Server')
        logger.info('Waiting for 2 seconds...')
        time.sleep(2)
