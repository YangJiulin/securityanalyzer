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
            'permissions': python_dict(db_entry[0].PERMISSIONS),
            'manifest_analysis': python_list(db_entry[0].MANIFEST_ANALYSIS),
            'network_security': python_list(db_entry[0].NETWORK_SECURITY),
            'code_analysis': python_dict(db_entry[0].CODE_ANALYSIS),
            'flow_analysis':python_list(db_entry[0].FLOW_REPORT),
            'urls': python_list(db_entry[0].URLS),
            'emails':python_list(db_entry[0].EMAILS),
            'exported_count': python_dict(db_entry[0].EXPORTED_COUNT),
        }
        return context
    except Exception:
        logger.exception('Fetching from DB')


def get_info_from_analysis(app_info,
                              man_data_dic,
                              man_an_dic,
                              code_an_dic,
                              flow_an_dic) -> dict:
    """从分析结果中获取APK/ZIP信息"""
    try:
        context = {
            'title': 'Static Analysis',
            'file_name': app_info['app_name'],
            'app_name': app_info['real_name'],
            'app_type': app_info['zipped'],
            'size': app_info['size'],
            'md5': app_info['md5'],
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
            'permissions': man_data_dic['permissions'],
            'manifest_analysis': man_an_dic['manifest_anal'],
            'network_security': man_an_dic['network_security'],
            'code_analysis': code_an_dic['findings'],
            'flow_analysis':flow_an_dic['results'],
            'urls': code_an_dic['urls'],
            'emails': code_an_dic['emails'],
            'exported_count': man_an_dic['exported_cnt'],
        }
        return context
    except Exception:
        logger.exception('Rendering to Template')


def save_or_update(update_type,
                   app_info,
                   man_data_dic,
                   man_an_dic,
                   code_an_dic,
                   flow_an_dic) -> None:
    """保存/更新APK/ZIP在数据库中的信息"""
    try:
        values = {
            'FILE_NAME': app_info['app_name'],
            'APP_NAME': app_info['real_name'],
            'APP_TYPE': app_info['zipped'],
            'SIZE': app_info['size'],
            'MD5': app_info['md5'],
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
            'PERMISSIONS': man_data_dic['permissions'],
            'MANIFEST_ANALYSIS': man_an_dic['manifest_anal'],
            'CODE_ANALYSIS': code_an_dic['findings'],
            'FLOW_REPORT':flow_an_dic['results'],
            'URLS': code_an_dic['urls'],
            'EMAILS':code_an_dic['emails'],
            'EXPORTED_COUNT': man_an_dic['exported_cnt'],
            'NETWORK_SECURITY': man_an_dic['network_security'],
        }
        if update_type == 'save':
            StaticAnalyzerAndroid.objects.create(**values)
        else:
            StaticAnalyzerAndroid.objects.filter(
                MD5=app_info['md5']).update(**values)
    except Exception:
        logger.exception('Updating DB')
