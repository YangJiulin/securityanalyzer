# -*- coding: utf_8 -*-
# flake8: noqa
"""Module for android manifest analysis."""
from StaticAnalyzer.views.dvm_permissions import DVM_PERMISSIONS
import logging
import os
from pathlib import Path
from xml.dom import minidom
from androguard.core.bytecodes import apk

from django.conf import settings

from securityanalyzer.utils import is_file_exists
from StaticAnalyzer.views import android_manifest_desc,network_security
# network_security,

logger = logging.getLogger(__name__)


def get_manifest(app_dir, typ,is_apk):
    """
    获取 manifest file.
    @return(filePath,readText)
    """
    try:
        manifest_file = get_manifest_file(app_dir,typ,is_apk)
        mfile = Path(manifest_file)
        if mfile.exists():
            manifest = mfile.read_text('utf-8', 'ignore')
        else:
            manifest = ''
        try:
            logger.info('Parsing AndroidManifest.xml')
            manifest = minidom.parseString(manifest)
        except Exception:
            err = ('apktool 未能提取'
                   'AndroidManifest.xml 或 转换失败')
            logger.exception(err)
            manifest = minidom.parseString(
                (r'<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android='
                 r'"http://schemas.android.com/apk/res/android" '
                 r'android:versionCode="Failed"  '
                 r'android:versionName="Failed" package="Failed"  '
                 r'platformBuildVersionCode="Failed" '
                 r'platformBuildVersionName="Failed XML Parsing" ></manifest>'))
            logger.warning('使用自定义虚假 XML 以继续分析')
        return manifest_file, manifest
    except Exception:
        logger.exception('Parsing Manifest file')


def get_manifest_data(app_path):
    """提取 manifest 数据."""
    try:
        logger.info('提取 Manifest 数据')
        _apk = apk.APK(app_path)
        services = _apk.get_services()
        activities = _apk.get_activities()
        receivers = _apk.get_receivers()
        providers = _apk.get_providers()
        libraries = _apk.get_libraries()
        permissions = _apk.get_details_permissions()
        packagename = _apk.get_package()
        min_sdk = _apk.get_min_sdk_version()
        max_sdk = _apk.get_max_sdk_version() if _apk.get_max_sdk_version() else _apk.get_target_sdk_version()
        target_sdk = _apk.get_target_sdk_version() if _apk.get_target_sdk_version() else _apk.get_max_sdk_version()
        mainactivity = _apk.get_main_activity()
        androidversioncode = _apk.get_androidversion_code()
        androidversionname = _apk.get_androidversion_name()
        man_data_dic = {
            'services': services,
            'activities': activities,
            'receivers': receivers,
            'providers': providers,
            'libraries': libraries,
            'permissions': permissions,
            'packagename': packagename,
            'mainactivity': mainactivity,
            'min_sdk': min_sdk,
            'max_sdk': max_sdk,
            'target_sdk': target_sdk,
            'androver': androidversioncode,
            'androvername': androidversionname,
        }

        return man_data_dic
    except Exception:
        logger.exception('正在提取 Manifest 数据')


def manifest_data(mfxml):
    """提取 manifest 数据."""
    try:
        logger.info('提取 Manifest 数据')
        svc = []
        act = []
        brd = []
        cnp = []
        lib = []
        perm = []
        cat = []
        icons = []
        dvm_perm = {}
        package = ''
        minsdk = ''
        maxsdk = ''
        targetsdk = ''
        mainact = ''
        androidversioncode = ''
        androidversionname = ''
        applications = mfxml.getElementsByTagName('application')
        permissions = mfxml.getElementsByTagName('uses-permission')
        manifest = mfxml.getElementsByTagName('manifest')
        activities = mfxml.getElementsByTagName('activity')
        services = mfxml.getElementsByTagName('service')
        providers = mfxml.getElementsByTagName('provider')
        receivers = mfxml.getElementsByTagName('receiver')
        libs = mfxml.getElementsByTagName('uses-library')
        sdk = mfxml.getElementsByTagName('uses-sdk')
        categories = mfxml.getElementsByTagName('category')
        for node in sdk:
            minsdk = node.getAttribute('android:minSdkVersion')
            maxsdk = node.getAttribute('android:maxSdkVersion')
            # Esteve 08.08.2016 - begin - If android:targetSdkVersion
            # is not set, the default value is the one of the
            # android:minSdkVersiontargetsdk
            # =node.getAttribute('android:targetSdkVersion')
            if node.getAttribute('android:targetSdkVersion'):
                targetsdk = node.getAttribute('android:targetSdkVersion')
            else:
                targetsdk = node.getAttribute('android:minSdkVersion')
            # End
        for node in manifest:
            package = node.getAttribute('package')
            androidversioncode = node.getAttribute('android:versionCode')
            androidversionname = node.getAttribute('android:versionName')
        alt_main = ''
        for activity in activities:
            act_2 = activity.getAttribute('android:name')
            act.append(act_2)
            if not mainact:
                # ^ Some manifest has more than one MAIN, take only
                # the first occurrence.
                for sitem in activity.getElementsByTagName('action'):
                    val = sitem.getAttribute('android:name')
                    if val == 'android.intent.action.MAIN':
                        mainact = activity.getAttribute('android:name')
                # Manifest has no MAIN, look for launch activity.
                for sitem in activity.getElementsByTagName('category'):
                    val = sitem.getAttribute('android:name')
                    if val == 'android.intent.category.LAUNCHER':
                        alt_main = activity.getAttribute('android:name')
        if not mainact and alt_main:
            mainact = alt_main

        for service in services:
            service_name = service.getAttribute('android:name')
            svc.append(service_name)

        for provider in providers:
            provider_name = provider.getAttribute('android:name')
            cnp.append(provider_name)

        for receiver in receivers:
            rec = receiver.getAttribute('android:name')
            brd.append(rec)

        for _lib in libs:
            libary = _lib.getAttribute('android:name')
            lib.append(libary)

        for category in categories:
            cat.append(category.getAttribute('android:name'))

        for permission in permissions:
            perm.append(permission.getAttribute('android:name'))
        android_permission_tags = ('com.google.', 'android.', 'com.google.')
        for full_perm in perm:
            prm = full_perm
            pos = full_perm.rfind('.')
            if pos != -1:
                prm = full_perm[pos + 1:]
            if not full_perm.startswith(android_permission_tags):
                prm = full_perm
            try:
                dvm_perm[full_perm] = DVM_PERMISSIONS[
                    'MANIFEST_PERMISSION'][prm]
            except KeyError:
                dvm_perm[full_perm] = [
                    'unknown',
                    'Unknown permission',
                    'Unknown permission from android reference',
                ]

        man_data_dic = {
            'services': svc,
            'activities': act,
            'receivers': brd,
            'providers': cnp,
            'libraries': lib,
            'categories': cat,
            'permissions': dvm_perm,
            'packagename': package,
            'mainactivity': mainact,
            'min_sdk': minsdk,
            'max_sdk': maxsdk,
            'target_sdk': targetsdk,
            'androver': androidversioncode,
            'androvername': androidversionname,
        }

        return man_data_dic
    except Exception:
        logger.exception('Extracting Manifest Data')



def get_browsable_activities(node):
    """
    node:activity结点
    能被浏览器调用 Activities.
    """
    try:
        browse_dic = {}
        schemes = []
        mime_types = []
        hosts = []
        ports = []
        paths = []
        path_prefixs = []
        path_patterns = []
        catg = node.getElementsByTagName('category')
        for cat in catg:
            if cat.getAttribute('android:name') == 'android.intent.category.BROWSABLE':
                datas = node.getElementsByTagName('data')
                for data in datas:
                    scheme = data.getAttribute('android:scheme')
                    if scheme and scheme not in schemes:
                        schemes.append(scheme)
                    mime = data.getAttribute('android:mimeType')
                    if mime and mime not in mime_types:
                        mime_types.append(mime)
                    host = data.getAttribute('android:host')
                    if host and host not in hosts:
                        hosts.append(host)
                    port = data.getAttribute('android:port')
                    if port and port not in ports:
                        ports.append(port)
                    path = data.getAttribute('android:path')
                    if path and path not in paths:
                        paths.append(path)
                    path_prefix = data.getAttribute('android:pathPrefix')
                    if path_prefix and path_prefix not in path_prefixs:
                        path_prefixs.append(path_prefix)
                    path_pattern = data.getAttribute('android:pathPattern')
                    if path_pattern and path_pattern not in path_patterns:
                        path_patterns.append(path_pattern)
        schemes = [scheme + '://' for scheme in schemes]
        browse_dic['schemes'] = schemes
        browse_dic['mime_types'] = mime_types
        browse_dic['hosts'] = hosts
        browse_dic['ports'] = ports
        browse_dic['paths'] = paths
        browse_dic['path_prefixs'] = path_prefixs
        browse_dic['path_patterns'] = path_patterns
        browse_dic['browsable'] = bool(browse_dic['schemes'])
        return browse_dic
    except Exception:
        logger.exception('获取可被浏览器调用 Activities')


def manifest_analysis(mfxml, man_data_dic, src_type, app_dir):
    """分析 manifest file."""
    try:
        logger.info('开始分析 Manifest')
        #四大组件导出个数
        exp_count = dict.fromkeys(['act', 'ser', 'bro', 'cnt'], 0)
        applications = mfxml.getElementsByTagName('application')
        datas = mfxml.getElementsByTagName('data')
        intents = mfxml.getElementsByTagName('intent-filter')
        actions = mfxml.getElementsByTagName('action')
        granturipermissions = mfxml.getElementsByTagName(
            'grant-uri-permission')
        #开发者自定义权限
        permissions = mfxml.getElementsByTagName('permission')
        ret_value = []
        ret_list = []
        exported = []
        browsable_activities = {}
        permission_dict = {}
        do_netsec = False
        debuggable = False
        cat = []
        categories = mfxml.getElementsByTagName('category')
        for category in categories:
            cat.append(category.getAttribute('android:name'))
        man_data_dic['categories'] = cat

        #自定义权限保护级别
        for permission in permissions:
            if permission.getAttribute('android:protectionLevel'):
                protectionlevel = permission.getAttribute(
                    'android:protectionLevel')
                logging.info(protectionlevel)
                if protectionlevel == '0x00000000':
                    protectionlevel = 'normal'
                elif protectionlevel == '0x00000001':
                    protectionlevel = 'dangerous'
                elif protectionlevel == '0x00000002':
                    protectionlevel = 'signature'
                elif protectionlevel == '0x00000003':
                    protectionlevel = 'signatureOrSystem'

                permission_dict[permission.getAttribute(
                    'android:name')] = protectionlevel
            elif permission.getAttribute('android:name'):
                permission_dict[permission.getAttribute(
                    'android:name')] = 'normal'

        # APPLICATIONS
        for application in applications:
            # application level
            if application.getAttribute('android:permission'):
                perm_appl_level_exists = True
                perm_appl_level = application.getAttribute(
                    'android:permission')
            else:
                perm_appl_level_exists = False
            # End
            if application.getAttribute('android:usesCleartextTraffic') == 'true':
                ret_list.append(('a_clear_text', (), ()))

            if application.getAttribute('android:debuggable') == 'true':
                ret_list.append(('a_debuggable', (), ()))
                debuggable = True

            if application.getAttribute('android:allowBackup') == 'true':
                ret_list.append(('a_allowbackup', (), ()))
            elif application.getAttribute('android:allowBackup') == 'false':
                pass
            else:
                ret_list.append(('a_allowbackup_miss', (), ()))

            if application.getAttribute('android:testOnly') == 'true':
                ret_list.append(('a_testonly', (), ()))

            for node in application.childNodes:
                if node.nodeName == 'activity':
                    itemname = 'Activity'
                    cnt_id = 'act'
                    browse_dic = get_browsable_activities(node)
                    if browse_dic['browsable']:
                        browsable_activities[node.getAttribute(
                            'android:name')] = browse_dic
                elif node.nodeName == 'activity-alias':
                    itemname = 'Activity-Alias'
                    cnt_id = 'act'
                    browse_dic = get_browsable_activities(node)
                    if browse_dic['browsable']:
                        browsable_activities[node.getAttribute(
                            'android:name')] = browse_dic

                elif node.nodeName == 'provider':
                    itemname = 'Content Provider'
                    cnt_id = 'cnt'
                elif node.nodeName == 'receiver':
                    itemname = 'Broadcast Receiver'
                    cnt_id = 'bro'
                elif node.nodeName == 'service':
                    itemname = 'Service'
                    cnt_id = 'ser'
                else:
                    itemname = 'NIL'
                item = ''

                # Task Affinity
                if (itemname in ['Activity', 'Activity-Alias'] and 
                    node.getAttribute('android:taskAffinity')
                ):
                    item = node.getAttribute('android:name')
                    ret_list.append(('a_taskaffinity', (item,), ()))

                # LaunchMode
                try:
                    affected_sdk = int(
                        man_data_dic['min_sdk']) < 21
                except Exception:
                    # 处理minsdk未声明的情况
                    affected_sdk = True

                if (affected_sdk and
                    itemname in ['Activity', 'Activity-Alias'] and
                    (node.getAttribute('android:launchMode') == 'singleInstance'
                        or node.getAttribute('android:launchMode') == 'singleTask')):
                    item = node.getAttribute('android:name')
                    ret_list.append(('a_launchmode', (item,), ()))

                # Exported检查
                item = ''
                is_inf = False
                is_perm_exist = False
                # 组件级别上存在与清单级别上的权限相匹配的权限

                prot_level_exist = False
                protlevel = ''
                # End
                if itemname != 'NIL':
                    if node.getAttribute('android:exported') == 'true':
                        perm = ''
                        item = node.getAttribute('android:name')
                        if node.getAttribute('android:permission'):
                            # 组件上存在权限
                            perm = ('<strong>Permission: </strong>'
                                    + node.getAttribute('android:permission'))
                            is_perm_exist = True
                        if item != man_data_dic['mainactivity']:
                            if is_perm_exist:
                                prot = ''
                                if node.getAttribute('android:permission') in permission_dict:
                                    prot = ('</br><strong>protectionLevel: </strong>'
                                            + permission_dict[node.getAttribute('android:permission')])
                                    """
                                    当声称组件受到权限的保护时，要考虑权限的保护级别;权限可能没有在正在分析的应用程序中定义，如果定义了，
                                    保护级别未知，导出的具有未知、正常或危险保护级别的活动(或活动别名)包含在导出的数据结构中，以便进一步处理;
                                    在这种情况下，组件也被算作导出。
                                    """
                                    # counted as exported.
                                    prot_level_exist = True
                                    protlevel = permission_dict[
                                        node.getAttribute('android:permission')]
                                if prot_level_exist:
                                    if protlevel == 'normal':
                                        ret_list.append(
                                            ('a_prot_normal', (itemname, item, perm + prot), (itemname)))
                                        if itemname in ['Activity', 'Activity-Alias']:
                                            exported.append(item)
                                        exp_count[cnt_id] = exp_count[
                                            cnt_id] + 1
                                    elif protlevel == 'dangerous':
                                        ret_list.append(
                                            ('a_prot_danger', (itemname, item, perm + prot), (itemname)))
                                        if itemname in ['Activity', 'Activity-Alias']:
                                            exported.append(item)
                                        exp_count[cnt_id] = exp_count[
                                            cnt_id] + 1
                                else:
                                    ret_list.append(
                                        ('a_prot_unknown', (itemname, item, perm), (itemname)))
                                    if itemname in ['Activity', 'Activity-Alias']:
                                        exported.append(item)
                                    exp_count[cnt_id] = exp_count[cnt_id] + 1
                            else:
                                """
                                在这一点上，我们处理的组件既没有组件级的权限，也没有应用程序级的权限。当它们被export时，它们不受保护。
                                """
                                if perm_appl_level_exists is False:
                                    ret_list.append(
                                        ('a_not_protected', (itemname, item), (itemname)))
                                    if itemname in ['Activity', 'Activity-Alias']:
                                        exported.append(item)
                                    exp_count[cnt_id] = exp_count[cnt_id] + 1

                                    """
                                    现在，我们处理的是在应用程序级别拥有权限的组件，而不是在组件级别拥有权限的组件,有两种选择:
                                    1)权限定义在manifest级别，这允许我们区分保护级别为我们在组件级别上指定了权限。
                                    2)权限没有在清单级别定义，这意味着保护级别是未知的，事实并非如此
                                    """

                                else:
                                    perm = '<strong>Permission: </strong>' + perm_appl_level
                                    prot = ''
                                    if perm_appl_level in permission_dict:
                                        prot = ('</br><strong>protectionLevel: </strong>'
                                                + permission_dict[perm_appl_level])
                                        prot_level_exist = True
                                        protlevel = permission_dict[
                                            perm_appl_level]
                                    if prot_level_exist:
                                        if protlevel == 'normal':
                                            ret_list.append(
                                                ('a_prot_normal_appl', (itemname, item, perm + prot), (itemname)))
                                            if itemname in ['Activity', 'Activity-Alias']:
                                                exported.append(item)
                                            exp_count[cnt_id] = exp_count[
                                                cnt_id] + 1
                                        elif protlevel == 'dangerous':
                                            ret_list.append(
                                                ('a_prot_danger_appl', (itemname, item, perm + prot), (itemname)))
                                            if itemname in ['Activity', 'Activity-Alias']:
                                                exported.append(item)
                                            exp_count[cnt_id] = exp_count[
                                                cnt_id] + 1
                                    else:
                                        ret_list.append(
                                            ('a_prot_unknown_appl', (itemname, item, perm), (itemname)))
                                        if itemname in ['Activity', 'Activity-Alias']:
                                            exported.append(item)
                                        exp_count[cnt_id] = exp_count[
                                            cnt_id] + 1

                    elif node.getAttribute('android:exported') != 'false':
                        """
                        检查是否隐式导出
                        支持intent-filter的逻辑
                        """
                        intentfilters = node.childNodes
                        for i in intentfilters:
                            inf = i.nodeName
                            if inf == 'intent-filter':
                                is_inf = True
                        if is_inf:
                            item = node.getAttribute('android:name')
                            if node.getAttribute('android:permission'):
                                # permission exists
                                perm = ('<strong>Permission: </strong>'
                                        + node.getAttribute('android:permission'))
                                is_perm_exist = True
                            if item != man_data_dic['mainactivity']:
                                if is_perm_exist:
                                    prot = ''
                                    if node.getAttribute('android:permission') in permission_dict:
                                        prot = ('</br><strong>protectionLevel: </strong>'
                                                + permission_dict[node.getAttribute('android:permission')])
                                        """
                                    当声称组件受到权限的保护时，要考虑权限的保护级别;权限可能没有在正在分析的应用程序中定义，如果定义了，
                                    保护级别未知，导出的具有未知、正常或危险保护级别的活动(或活动别名)包含在导出的数据结构中，以便进一步处理;
                                    在这种情况下，组件也被算作导出。
                                        """
                                        prot_level_exist = True
                                        protlevel = permission_dict[
                                            node.getAttribute('android:permission')]
                                        if prot_level_exist:
                                            if protlevel == 'normal':
                                                ret_list.append(
                                                    ('a_prot_normal', (itemname, item, perm + prot), (itemname)))
                                                if itemname in ['Activity', 'Activity-Alias']:
                                                    exported.append(item)
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                            elif protlevel == 'dangerous':
                                                ret_list.append(
                                                    ('a_prot_danger', (itemname, item, perm + prot), (itemname)))
                                                if itemname in ['Activity', 'Activity-Alias']:
                                                    exported.append(item)
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                    else:
                                        ret_list.append(
                                            ('a_prot_unknown', (itemname, item, perm), (itemname)))
                                        if itemname in ['Activity', 'Activity-Alias']:
                                            exported.append(item)
                                        exp_count[cnt_id] = exp_count[
                                            cnt_id] + 1
                                else:
                                    if perm_appl_level_exists is False:
                                        ret_list.append(
                                            ('a_not_protected_filter', (itemname, item), (itemname, itemname)))
                                        if itemname in ['Activity', 'Activity-Alias']:
                                            exported.append(item)
                                        exp_count[cnt_id] = exp_count[
                                            cnt_id] + 1
                                    
                                    else:
                                        perm = '<strong>Permission: </strong>' + perm_appl_level
                                        prot = ''
                                        if perm_appl_level in permission_dict:
                                            prot = ('</br><strong>protectionLevel: </strong>'
                                                    + permission_dict[perm_appl_level])
                                            prot_level_exist = True
                                            protlevel = permission_dict[
                                                perm_appl_level]
                                        if prot_level_exist:
                                            if protlevel == 'normal':
                                                ret_list.append(
                                                    ('a_prot_normal_appl', (itemname, item, perm + prot), (itemname)))
                                                if itemname in ['Activity', 'Activity-Alias']:
                                                    exported.append(item)
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                            elif protlevel == 'dangerous':
                                                ret_list.append(
                                                    ('a_prot_danger_appl', (itemname, item, perm + prot), (itemname)))
                                                if itemname in ['Activity', 'Activity-Alias']:
                                                    exported.append(item)
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                        else:
                                            ret_list.append(
                                                ('a_prot_unknown_appl', (itemname, item, perm), (itemname)))
                                            if itemname in ['Activity', 'Activity-Alias']:
                                                exported.append(item)
                                            exp_count[cnt_id] = exp_count[
                                                cnt_id] + 1

        # GRANT-URI-PERMISSIONS
        for granturi in granturipermissions:
            if granturi.getAttribute('android:pathPrefix') == '/':
                ret_list.append(
                    ('a_improper_provider', ('pathPrefix=/',), ()))
            elif granturi.getAttribute('android:path') == '/':
                ret_list.append(('a_improper_provider', ('path=/',), ()))
            elif granturi.getAttribute('android:pathPattern') == '*':
                ret_list.append(('a_improper_provider', ('path=*',), ()))
        # DATA
        for data in datas:
            if data.getAttribute('android:scheme') == 'android_secret_code':
                xmlhost = data.getAttribute('android:host')
                ret_list.append(('a_dailer_code', (xmlhost,), ()))

            elif data.getAttribute('android:port'):
                dataport = data.getAttribute('android:port')
                ret_list.append(('a_sms_receiver_port', (dataport,), ()))
        # INTENTS
        for intent in intents:
            if intent.getAttribute('android:priority').isdigit():
                value = intent.getAttribute('android:priority')
                if int(value) > 100:
                    ret_list.append(
                        ('a_high_intent_priority', (value,), ()))
        # ACTIONS
        for action in actions:
            if action.getAttribute('android:priority').isdigit():
                value = action.getAttribute('android:priority')
                if int(value) > 100:
                    ret_list.append(
                        ('a_high_action_priority', (value,), ()))

        for a_key, t_name, t_desc in ret_list:
            a_template = android_manifest_desc.MANIFEST_DESC.get(a_key)
            if a_template:  
                ret_value.append(
                    {'title': a_template['title'] % t_name,
                     'stat': a_template['level'],
                     'desc': a_template['description'] % t_desc,
                     'name': a_template['name'],
                     'component': t_name,
                     })

        exported_comp = {
            'exported_activities': exp_count['act'],
            'exported_services': exp_count['ser'],
            'exported_receivers': exp_count['bro'],
            'exported_providers': exp_count['cnt'],
        }
        man_an_dic = {
            'manifest_anal': ret_value,
            'exported_act': exported,
            'exported_cnt': exported_comp,
            'browsable_activities': browsable_activities,
            'network_security': network_security.analysis(
                app_dir,
                do_netsec,
                debuggable,
                src_type),
        }
        return man_an_dic
    except Exception:
        logger.exception('Performing Manifest Analysis')


def get_manifest_file(app_dir,typ, apk):
    """Read the manifest file."""
    try:
        manifest = ''
        if apk:
            logger.info('从 APK 获取AndroidManifest.xml ')
            manifest_dir = os.path.join(app_dir, 'apktool_out')
            manifest = os.path.join(manifest_dir, 'AndroidManifest.xml')
            if is_file_exists(manifest):
            # APKTool already created readable XML
                return manifest
        else:
            logger.info('正在从源代码获取 AndroidManifest.xml')
            if typ == 'eclipse':
                manifest = os.path.join(app_dir, 'AndroidManifest.xml')
            elif typ == 'studio':
                manifest = os.path.join(
                    app_dir,
                    'app/src/main/AndroidManifest.xml')
        return manifest
    except Exception:
        logger.exception('正在获取 AndroidManifest.xml 文件')
