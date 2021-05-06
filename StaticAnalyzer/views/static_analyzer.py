# -*- coding: utf_8 -*-
"""Android Static Code Analysis."""

from StaticAnalyzer.views.flow_analysis import flow_analysis
import shutil
from StaticAnalyzer.views.shared_func import unzip, update_scan_timestamp
from StaticAnalyzer.views.code_analysis import code_analysis
from StaticAnalyzer.views.manifest_analysis import get_manifest, get_manifest_data, manifest_analysis
import logging
import os
import re
from securityanalyzer.utils import can_run_flow, file_size, is_dir_exists, is_file_exists, print_n_send_error_response

from django.conf import settings
from django.shortcuts import render
from django.template.defaulttags import register
 
from StaticAnalyzer.models import RecentScansDB, StaticAnalyzerAndroid

from Home.views.converter import apk_2_java,unzip_apk_apktool
from .db_operation import get_info_from_analysis,get_info_from_db_entry,save_or_update

logger = logging.getLogger(__name__)


@register.filter
def key(data, key_name):
    """Return the data for a key_name."""
    return data.get(key_name)


def static_analyzer(request):
    typ = request.GET['type']
    checksum = request.GET['checksum']
    filename = request.GET['name']
    rescan = str(request.GET.get('rescan', 0))

    app_info = {}
    match = re.match('^[0-9a-f]{32}$', checksum)
    if (match and filename.lower().endswith(('.apk', '.zip'))and typ in ['zip', 'apk']):
        app_info['app_name'] = filename  # APP ORGINAL NAME
        app_info['md5'] = checksum  # MD5
        # APP DIRECTORY
        app_info['app_dir'] = settings.MEDIA_ROOT / 'upload' / checksum   #APK所在文件夹路径
        app_info['tools_dir'] =settings.BASE_DIR / 'StaticAnalyzer' / 'tools'
        app_info['tools_dir'] = app_info['tools_dir'].as_posix()
        logger.info('开始分析 : %s' , app_info['app_name'])
        if typ == 'apk':
            app_info['app_file'] = app_info['md5'] + '.apk'  # NEW FILENAME
            app_info['app_path'] = (
                app_info['app_dir'] / app_info['app_file']).as_posix()    #apk文件路径
            app_info['app_dir'] = app_info['app_dir'].as_posix() + '/'
            #检查数据库中是否已经有该app的分析数据
            re_db_entry = RecentScansDB.objects.get(MD5=app_info['md5'])
            db_entry = StaticAnalyzerAndroid.objects.filter(
                    MD5=app_info['md5'])
            if db_entry.exists() and rescan == '0':
                    context = get_info_from_db_entry(db_entry)
            else:
                # 开始分析
                unzip_apk_apktool(app_path=app_info['app_path'],app_dir= app_info['app_dir'],tools_dir=app_info['tools_dir'])
                apk_2_java(app_info['app_path'], app_info['app_dir'],
                               app_info['tools_dir'])
                app_info['size'] = str(file_size(app_info['app_path'])) + 'MB'  # FILE SIZE
                logger.info('解压APK')
                # Manifest XML
                mani_file, mani_xml = get_manifest(
                        app_info['app_dir'],
                        '',
                        True,
                    )
                app_info['manifest_file'] = mani_file
                app_info['parsed_xml'] = mani_xml
                # get app_name
                app_info['real_name'] = re_db_entry.APP_NAME
                # Set Manifest link
                app_info['mani'] = ('../manifest_view/?md5='
                                       + app_info['md5']
                                       + '&type=apfk&bin=1')
                
                manifest_data_dict = get_manifest_data(app_info['app_path'])

#=====================================manifest_analysis===========================================
                manifest_analysis_dict =  manifest_analysis(
                        app_info['parsed_xml'],
                        manifest_data_dict,
                        '',
                        app_info['app_dir'],
                    )
#=====================================code_analysis===========================================      
                code_an_dic = code_analysis(
                        app_info['app_dir'],
                        'apk',)

                app_info['zipped'] = 'apk'
#=====================================flow_analysis=========================================== 
                if can_run_flow():
                    flow_an_dic = flow_analysis(
                        app_info['app_dir'],
                        app_info['app_path'],
                        app_info['tools_dir'],
                        manifest_data_dict['target_sdk']
                    )
                else:
                    flow_an_dic = {"results":[]}
                    logging.error('当前设备可用内存小于2GB，不能执行污点分析',)

                logger.info('连接数据库')
                try:
                    # SAVE TO DB
                    if rescan == '1':
                        logger.info('更新数据...')
                        save_or_update(
                                'update',
                                app_info,
                                manifest_data_dict,
                                manifest_analysis_dict,
                                code_an_dic,
                                flow_an_dic,
                            )
                        update_scan_timestamp(app_info['md5'])
                    elif rescan == '0':
                        logger.info('Saving to Database')
                        save_or_update(
                                'save',
                                app_info,
                                manifest_data_dict,
                                manifest_analysis_dict,
                                code_an_dic,
                                flow_an_dic
                            )
                except Exception:
                    logger.exception('保存到数据库失败')
                context = get_info_from_analysis(
                        app_info,
                        manifest_data_dict,
                        manifest_analysis_dict,
                        code_an_dic,
                        flow_an_dic,
                    )
            context['dynamic_analysis_done'] = is_file_exists(
                    os.path.join(app_info['app_dir'], 'logcat.txt'))
            calculate_category(context)
            template = 'static_analysis/android_binary_analysis.html'
            return render(request, template, context)
        elif typ == 'zip':
                app_info['zipped'] = ''
                # Above fields are only available for APK and not ZIP
                app_info['app_file'] = app_info['md5'] + '.zip'  # NEW FILENAME
                app_info['app_path'] = (
                    app_info['app_dir'] / app_info['app_file']).as_posix()
                app_info['app_dir'] = app_info['app_dir'].as_posix() + '/'
                db_entry = StaticAnalyzerAndroid.objects.filter(
                    MD5=app_info['md5'])
                if db_entry.exists() and rescan == '0':
                    context = get_info_from_db_entry(db_entry)
                else:
                    logger.info('解压ZIP')
                    app_info['files'] = unzip(
                        app_info['app_path'], app_info['app_dir'])
                    # Check if Valid Directory Structure and get ZIP Type
                    pro_type, valid = valid_source_code(app_info['app_dir'])
                    logger.info('源代码类型 - %s', pro_type)
                    app_info['zipped'] = pro_type
                    if valid and (pro_type in ['eclipse', 'studio']):
                        # ANALYSIS BEGINS
                        app_info['size'] = str(
                            file_size(app_info['app_path'])) + 'MB'  # FILE SIZE

                        # Manifest XML
                        mani_file, mani_xml = get_manifest(
                            app_info['app_dir'],
                            pro_type,
                            False,
                        )
                        app_info['manifest_file'] = mani_file
                        app_info['parsed_xml'] = mani_xml

                        # get app_name
                        app_info['real_name'] = ''

                        # Set manifest view link
                        app_info['mani'] = (
                            '../manifest_view/?md5='
                            + app_info['md5'] + '&type='
                            + pro_type + '&bin=0'
                        )

                        manifest_data_dict = get_manifest_data(app_info['app_path'])
                        man_an_dic = manifest_analysis(
                            app_info['parsed_xml'],
                            manifest_data_dict,
                            pro_type,
                            app_info['app_dir'],
                        )
                        code_an_dic = code_analysis(
                            app_info['app_dir'],
                            pro_type,
                            app_info['manifest_file'])

                        flow_an_dic = {'results':[]}

                        logger.info('连接数据库')
                        try:
                            # SAVE TO DB
                            if rescan == '1':
                                logger.info('更新数据...')
                                save_or_update(
                                    'update',
                                    app_info,
                                    manifest_data_dict,
                                    man_an_dic,
                                    code_an_dic,
                                    flow_an_dic
                                )
                                update_scan_timestamp(app_info['md5'])
                            elif rescan == '0':
                                logger.info('保存到数据库')
                                save_or_update(
                                    'save',
                                    app_info,
                                    manifest_data_dict,
                                    man_an_dic,
                                    code_an_dic,
                                    flow_an_dic
                                )
                        except Exception:
                            logger.exception('保存到数据库失败')
                        context = get_info_from_analysis(
                            app_info,
                            manifest_data_dict,
                            man_an_dic,
                            code_an_dic,
                            flow_an_dic
                        )
                        calculate_category(context)
                    else:
                        msg = '不支持此ZIP格式'
                        print_n_send_error_response(request, msg, False)
                        ctx = {
                                'title': '无效的ZIP归档',
                            }
                        template = 'general/zip.html'
                        return render(request, template, ctx)
                template = 'static_analysis/android_binary_analysis.html'
                return render(request, template, context)
        logger.info('分析成功 : %s' , app_info['app_name'])
    else:
        msg = '哈希匹配失败或无效的文件扩展名或文件类型'
        return print_n_send_error_response(request, msg, True)

def calculate_category(context):
    code_anal = context['code_analysis']
    mani_anal = context['manifest_analysis']
    flow_anal = context['flow_analysis']
    permiss = context['permissions']
    category = {}
    category['mani_count'] = len(mani_anal)
    category['flow_count'] = len(flow_anal)
    category['SSL_count'] = 0
    category['WebView_count'] = 0
    category['data_count'] = 0
    category['highPermiss_count']=0
    for _,value in code_anal.items():
        if value['metadata']['category'] == 'DATA':
            category['data_count'] += 1
        elif value['metadata']['category'] == 'SSL':
            category['SSL_count'] += 1
        elif value['metadata']['category'] == 'WebView':
            category['WebView_count'] += 1
    for _,v in permiss.items():
        if v[0] == 'dangerous':
            category['highPermiss_count']+=1
    context['category'] = category




def move_to_parent(inside, app_dir):
    """Move contents of inside to app dir."""
    for x in os.listdir(inside):
        full_path = os.path.join(inside, x)
        shutil.move(full_path, app_dir)
    shutil.rmtree(inside)


def is_android_source(app_dir):
    """Detect Android Source and IDE Type."""
    # Eclipse
    man = os.path.isfile(os.path.join(app_dir, 'AndroidManifest.xml'))
    src = os.path.exists(os.path.join(app_dir, 'src/'))
    if man and src:
        return 'eclipse', True
    # Studio
    man = os.path.isfile(
        os.path.join(app_dir, 'app/src/main/AndroidManifest.xml'),
    )
    java = os.path.exists(os.path.join(app_dir, 'app/src/main/java/'))
    kotlin = os.path.exists(os.path.join(app_dir, 'app/src/main/kotlin/'))
    if man and (java or kotlin):
        return 'studio', True
    return None, False

def valid_source_code(app_dir):
    """Test if this is an valid source code zip."""
    try:
        logger.info('Detecting source code type')
        ide, is_and = is_android_source(app_dir)
        if ide:
            return ide, is_and
        # Relaxed Android Source check, one level down
        for x in os.listdir(app_dir):
            obj = os.path.join(app_dir, x)
            if not is_dir_exists(obj):
                continue
            ide, is_and = is_android_source(obj)
            if ide:
                move_to_parent(obj, app_dir)
                return ide, is_and
    except Exception:
        logger.exception('Identifying source code from zip')