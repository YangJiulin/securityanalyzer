# -*- coding: utf_8 -*-
"""处理并分析动态分析数据"""
import io
import logging
import os
import re
import shutil
import tarfile
from pathlib import Path

from securityanalyzer.utils import (
    is_file_exists,
    is_pipe_or_link,
    python_list,
)
from StaticAnalyzer.models import StaticAnalyzerAndroid

logger = logging.getLogger(__name__)


def run_analysis(apk_dir, md5_hash, package):
    """动态分析日志分析"""
    analysis_result = {}
    logger.info('动态文件分析')
    # Collect Log data
    datas = get_log_data(apk_dir, package)
    # URLs My Custom regex
    url_pattern = re.compile(
        r'((?:https?://|s?ftps?://|file://|'
        r'javascript:|data:|www\d{0,3}'
        r'[.])[\w().=/;,#:@?&~*+!$%\'{}-]+)', re.UNICODE)
    urls = re.findall(url_pattern, datas['traffic'].lower())
    if urls:
        urls = list(set(urls))
    else:
        urls = []
    # Domain提取和恶意检查
    logger.info('对提取出的链接进行检查')
    # Email Etraction Regex
    emails = []
    regex = re.compile(r'[\w.-]{1,20}@[\w-]{1,20}\.[\w]{2,10}')
    for email in regex.findall(datas['traffic'].lower()):
        if (email not in emails) and (not email.startswith('//')):
            emails.append(email)
    # Tar dump and fetch files
    all_files = get_app_files(apk_dir, md5_hash, package)
    analysis_result['urls'] = urls
    analysis_result['emails'] = emails
    analysis_result['xml'] = all_files['xml']
    analysis_result['sqlite'] = all_files['sqlite']
    analysis_result['other_files'] = all_files['others']
    return analysis_result


def get_screenshots(md5_hash, download_dir):
    """获取屏幕截图"""
    # Only After Download Process is Done
    result = {}
    imgs = []
    expact_imgs = []
    exp_act = {}
    try:
        screen_dir = os.path.join(download_dir,md5_hash ,'screenshots-apk/')
        sadb = StaticAnalyzerAndroid.objects.get(MD5=md5_hash)
        if os.path.exists(screen_dir):
            for img in os.listdir(screen_dir):
                if img.endswith('.png'):
                    if img.startswith('expact'):
                        expact_imgs.append(img)
                    else:
                        imgs.append(img)
            exported_act = python_list(sadb.EXPORTED_ACTIVITIES)
            if expact_imgs:
                if len(expact_imgs) == len(exported_act):
                    exp_act = dict(list(zip(expact_imgs, exported_act)))
    except Exception:
        logger.exception('获取截图')
    result['screenshots'] = imgs
    result['exported_activities'] = exp_act
    return result


def get_log_data(apk_dir, package):
    """Get Data for analysis."""
    logcat_data = []
    apimon_data = ''
    frida_logs = ''
    web_data = ''
    traffic = ''
    logcat = os.path.join(apk_dir, 'logcat.txt')
    apimon = os.path.join(apk_dir, 'api_monitor.txt')
    fd_logs = os.path.join(apk_dir, 'frida_out.txt')
    if is_file_exists(logcat):
        with io.open(logcat,
                     mode='r',
                     encoding='utf8',
                     errors='ignore') as flip:
            logcat_data = flip.readlines()
            traffic = ''.join(logcat_data)
    if is_file_exists(apimon):
        with io.open(apimon,
                     mode='r',
                     encoding='utf8',
                     errors='ignore') as flip:
            apimon_data = flip.read()
    if is_file_exists(fd_logs):
        with io.open(fd_logs,
                     mode='r',
                     encoding='utf8',
                     errors='ignore') as flip:
            frida_logs = flip.read()
    traffic = (web_data + traffic
               + apimon_data + frida_logs)
    return {'logcat': logcat_data,
            'traffic': traffic}


def get_app_files(apk_dir, md5_hash, package):
    """在打包APP文件后，解压并获取文件基础信息（没有具体内容）"""
    logger.info('Getting app files')
    all_files = {'xml': [], 'sqlite': [], 'others': []}
    # Extract Device Data
    tar_loc = os.path.join(apk_dir, package + '.tar')
    untar_dir = os.path.join(apk_dir, 'DYNAMIC_DeviceData/')
    if not is_file_exists(tar_loc):
        return all_files
    if os.path.exists(untar_dir):
        # fix for permission errors
        shutil.rmtree(untar_dir)
    try:
        with tarfile.open(tar_loc, errorlevel=1) as tar:
            tar.extractall(untar_dir)
    except FileExistsError:
        pass
    except Exception:
        logger.exception('Tar extraction failed')
    # Do Static Analysis on Data from Device
    try:
        if not os.path.exists(untar_dir):
            os.makedirs(untar_dir)
        for dir_name, _, files in os.walk(untar_dir):
            for jfile in files:
                file_path = os.path.join(untar_dir, dir_name, jfile)
                fileparam = file_path.replace(untar_dir, '')
                if is_pipe_or_link(file_path):
                    continue
                if jfile == 'lib':
                    pass
                else:
                    if jfile.endswith('.xml'):
                        all_files['xml'].append(
                            {'type': 'xml', 'file': fileparam})
                    else:
                        with open(file_path,
                                  'r',
                                  encoding='ISO-8859-1') as flip:
                            file_cnt_sig = flip.read(6)
                        if file_cnt_sig == 'SQLite':
                            all_files['sqlite'].append(
                                {'type': 'db', 'file': fileparam})
                        elif not jfile.endswith('.DS_Store'):
                            all_files['others'].append(
                                {'type': 'others', 'file': fileparam})
    except Exception:
        logger.exception('Getting app files')
    return all_files


def generate_download(apk_dir, md5_hash, download_dir, package):
    """Generating Downloads."""
    logger.info('Generating Downloads')
    try:
        httptools = os.path.join(str(Path.home()), '.httptools')
        logcat = os.path.join(apk_dir, 'logcat.txt')
        apimon = os.path.join(apk_dir, 'api_monitor.txt')
        fd_logs = os.path.join(apk_dir, 'frida_out.txt')
        dumpsys = os.path.join(apk_dir, 'dump.txt')
        sshot = os.path.join(apk_dir, 'screenshots-apk/')
        web = os.path.join(httptools, 'flows', package + '.flow.txt')
        star = os.path.join(apk_dir, package + '.tar')

        dlogcat = os.path.join(download_dir,md5_hash, md5_hash + '-logcat.txt')
        dapimon = os.path.join(download_dir,md5_hash, md5_hash + '-api_monitor.txt')
        dfd_logs = os.path.join(download_dir,md5_hash, md5_hash + '-frida_out.txt')
        ddumpsys = os.path.join(download_dir, md5_hash,md5_hash + '-dump.txt')
        dsshot = os.path.join(download_dir,md5_hash, 'screenshots-apk/')
        dweb = os.path.join(download_dir, md5_hash,md5_hash + '-web_traffic.txt')
        dstar = os.path.join(download_dir, md5_hash,md5_hash + '-app_data.tar')

        # Delete existing data
        dellist = [dlogcat,dapimon,
                   dfd_logs, ddumpsys, dsshot,
                   dweb, dstar]
        for item in dellist:
            if os.path.isdir(item):
                shutil.rmtree(item)
            elif os.path.isfile(item):
                os.remove(item)
        # Copy new data
        shutil.copyfile(logcat, dlogcat)
        shutil.copyfile(dumpsys, ddumpsys)
        if is_file_exists(apimon):
            shutil.copyfile(apimon, dapimon)
        if is_file_exists(fd_logs):
            shutil.copyfile(fd_logs, dfd_logs)
        try:
            shutil.copytree(sshot, dsshot)
        except Exception:
            pass
        if is_file_exists(web):
            shutil.copyfile(web, dweb)
        if is_file_exists(star):
            shutil.copyfile(star, dstar)
    except Exception:
        logger.exception('Generating Downloads')
