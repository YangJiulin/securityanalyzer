# -*- coding: utf_8 -*-
import logging

from django.conf import settings
from django.db.models import QuerySet

from securityanalyzer.utils import python_dict, python_list
from StaticAnalyzer.models import StaticAnalyzerAndroid
from StaticAnalyzer.models import RecentScansDB

logger = logging.getLogger(__name__)


def get_info_from_db_entry(db_entry: QuerySet) -> dict:
    """从数据库中得到APK/ZIP信息"""
    try:
        logger.info('分析已完成，从数据库中获取信息')
        context = {
            'title': 'Static Analysis',
            'file_name': db_entry[0].FILE_NAME,
            'app_name': db_entry[0].APP_NAME,
            'app_type': db_entry[0].APP_TYPE,
            'size': db_entry[0].SIZE,
            'md5': db_entry[0].MD5,
            'package_name': db_entry[0].PACKAGE_NAME,
            'main_activity': db_entry[0].MAIN_ACTIVITY,
            'exported_activities': db_entry[0].EXPORTED_ACTIVITIES,
            'browsable_activities': python_dict(
                db_entry[0].BROWSABLE_ACTIVITIES),
            'activities': python_list(db_entry[0].ACTIVITIES),
            'receivers': python_list(db_entry[0].RECEIVERS),
            'providers': python_list(db_entry[0].PROVIDERS),
            'services': python_list(db_entry[0].SERVICES),
            'libraries': python_list(db_entry[0].LIBRARIES),
            'target_sdk': db_entry[0].TARGET_SDK,
            'max_sdk': db_entry[0].MAX_SDK,
            'min_sdk': db_entry[0].MIN_SDK,
            'version_name': db_entry[0].VERSION_NAME,
            'version_code': db_entry[0].VERSION_CODE,
            'icon_hidden': db_entry[0].ICON_HIDDEN,
            'icon_found': db_entry[0].ICON_FOUND,
            'permissions': python_dict(db_entry[0].PERMISSIONS),
            'certificate_analysis': python_dict(
                db_entry[0].CERTIFICATE_ANALYSIS),
            'manifest_analysis': python_list(db_entry[0].MANIFEST_ANALYSIS),
            'network_security': python_list(db_entry[0].NETWORK_SECURITY),
            'binary_analysis': python_list(db_entry[0].BINARY_ANALYSIS),
            'file_analysis': python_list(db_entry[0].FILE_ANALYSIS),
            'android_api': python_dict(db_entry[0].ANDROID_API),
            'code_analysis': python_dict(db_entry[0].CODE_ANALYSIS),
            'niap_analysis': python_dict(db_entry[0].NIAP_ANALYSIS),
            'urls': python_list(db_entry[0].URLS),
            'domains': python_dict(db_entry[0].DOMAINS),
            'emails': python_list(db_entry[0].EMAILS),
            'strings': python_list(db_entry[0].STRINGS),
            'firebase_urls': python_list(db_entry[0].FIREBASE_URLS),
            'files': python_list(db_entry[0].FILES),
            'exported_count': python_dict(db_entry[0].EXPORTED_COUNT),
            'apkid': python_dict(db_entry[0].APKID),
            'trackers': python_dict(db_entry[0].TRACKERS),
            'playstore_details': python_dict(db_entry[0].PLAYSTORE_DETAILS),
            'secrets': python_list(db_entry[0].SECRETS),
        }
        return context
    except Exception:
        logger.exception('Fetching from DB')


def get_info_from_analysis(app_info,
                              man_data_dic,
                              man_an_dic,
                              code_an_dic,
                              cert_dic,
                              bin_anal,
                              apk_id,
                              trackers) -> dict:
    """从分析结果中获取APK/ZIP信息"""
    try:
        context = {
            'title': 'Static Analysis',
            'file_name': app_info['app_name'],
            'app_name': app_info['real_name'],
            'app_type': app_info['zipped'],
            'size': app_info['size'],
            'md5': app_info['md5'],
            'sha1': app_info['sha1'],
            'sha256': app_info['sha256'],
            'package_name': man_data_dic['packagename'],
            'main_activity': man_data_dic['mainactivity'],
            'exported_activities': man_an_dic['exported_act'],
            'browsable_activities': man_an_dic['browsable_activities'],
            'activities': man_data_dic['activities'],
            'receivers': man_data_dic['receivers'],
            'providers': man_data_dic['providers'],
            'services': man_data_dic['services'],
            'libraries': man_data_dic['libraries'],
            'target_sdk': man_data_dic['target_sdk'],
            'max_sdk': man_data_dic['max_sdk'],
            'min_sdk': man_data_dic['min_sdk'],
            'version_name': man_data_dic['androvername'],
            'version_code': man_data_dic['androver'],
            'icon_hidden': app_info['icon_hidden'],
            'icon_found': app_info['icon_found'],
            'certificate_analysis': cert_dic,
            'permissions': man_an_dic['permissons'],
            'manifest_analysis': man_an_dic['manifest_anal'],
            'network_security': man_an_dic['network_security'],
            'binary_analysis': bin_anal,
            'file_analysis': app_info['certz'],
            'android_api': code_an_dic['api'],
            'code_analysis': code_an_dic['findings'],
            'niap_analysis': code_an_dic['niap'],
            'urls': code_an_dic['urls'],
            'domains': code_an_dic['domains'],
            'emails': code_an_dic['emails'],
            'strings': app_info['strings'],
            'firebase_urls': code_an_dic['firebase'],
            'files': app_info['files'],
            'exported_count': man_an_dic['exported_cnt'],
            'apkid': apk_id,
            'trackers': trackers,
            'playstore_details': app_info['playstore'],
            'secrets': app_info['secrets'],
        }
        return context
    except Exception:
        logger.exception('Rendering to Template')


def save_or_update(update_type,
                   app_info,
                   man_data_dic,
                   man_an_dic,
                   code_an_dic,
                   cert_dic,
                   bin_anal,
                   apk_id,
                   trackers) -> None:
    """保存/更新APK/ZIP在数据库中的信息"""
    try:
        values = {
            'FILE_NAME': app_info['app_name'],
            'APP_NAME': app_info['real_name'],
            'APP_TYPE': app_info['zipped'],
            'SIZE': app_info['size'],
            'MD5': app_info['md5'],
            'SHA1': app_info['sha1'],
            'SHA256': app_info['sha256'],
            'PACKAGE_NAME': man_data_dic['packagename'],
            'MAIN_ACTIVITY': man_data_dic['mainactivity'],
            'EXPORTED_ACTIVITIES': man_an_dic['exported_act'],
            'BROWSABLE_ACTIVITIES': man_an_dic['browsable_activities'],
            'ACTIVITIES': man_data_dic['activities'],
            'RECEIVERS': man_data_dic['receivers'],
            'PROVIDERS': man_data_dic['providers'],
            'SERVICES': man_data_dic['services'],
            'LIBRARIES': man_data_dic['libraries'],
            'TARGET_SDK': man_data_dic['target_sdk'],
            'MAX_SDK': man_data_dic['max_sdk'],
            'MIN_SDK': man_data_dic['min_sdk'],
            'VERSION_NAME': man_data_dic['androvername'],
            'VERSION_CODE': man_data_dic['androver'],
            'ICON_HIDDEN': app_info['icon_hidden'],
            'ICON_FOUND': app_info['icon_found'],
            'CERTIFICATE_ANALYSIS': cert_dic,
            'PERMISSIONS': man_an_dic['permissons'],
            'MANIFEST_ANALYSIS': man_an_dic['manifest_anal'],
            'BINARY_ANALYSIS': bin_anal,
            'FILE_ANALYSIS': app_info['certz'],
            'ANDROID_API': code_an_dic['api'],
            'CODE_ANALYSIS': code_an_dic['findings'],
            'NIAP_ANALYSIS': code_an_dic['niap'],
            'URLS': code_an_dic['urls'],
            'DOMAINS': code_an_dic['domains'],
            'EMAILS': code_an_dic['emails'],
            'STRINGS': app_info['strings'],
            'FIREBASE_URLS': code_an_dic['firebase'],
            'FILES': app_info['files'],
            'EXPORTED_COUNT': man_an_dic['exported_cnt'],
            'APKID': apk_id,
            'TRACKERS': trackers,
            'PLAYSTORE_DETAILS': app_info['playstore'],
            'NETWORK_SECURITY': man_an_dic['network_security'],
            'SECRETS': app_info['secrets'],
        }
        if update_type == 'save':
            StaticAnalyzerAndroid.objects.create(**values)
        else:
            StaticAnalyzerAndroid.objects.filter(
                MD5=app_info['md5']).update(**values)
    except Exception:
        logger.exception('Updating DB')
    try:
        values = {
            'APP_NAME': app_info['real_name'],
            'PACKAGE_NAME': man_data_dic['packagename'],
            'VERSION_NAME': man_data_dic['androvername'],
        }
        RecentScansDB.objects.filter(
            MD5=app_info['md5']).update(**values)
    except Exception:
        logger.exception('Updating RecentScansDB')
