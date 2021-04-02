# -*- coding: utf_8 -*-
"""Android Static Code Analysis."""

from StaticAnalyzer.views.code_analysis import code_analysis
from StaticAnalyzer.views.manifest_analysis import get_manifest, get_manifest_data, manifest_analysis
import logging
import os
import json
import re
import collections
from securityanalyzer.utils import file_size, get_config_loc, is_file_exists, print_n_send_error_response
import shutil
from pathlib import Path

from django.conf import settings
from django.http import HttpResponseRedirect
from django.http.response import HttpResponse
from django.shortcuts import render
from django.template.defaulttags import register

from androguard.core.bytecodes import apk    
from StaticAnalyzer.models import RecentScansDB, StaticAnalyzerAndroid

from Home.views.converter import apk_2_java, unzip_apk_apktool
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
        app_info['dir'] = settings.BASE_DIR  # BASE DIR
        app_info['app_name'] = filename  # APP ORGINAL NAME
        app_info['md5'] = checksum  # MD5
        # APP DIRECTORY
        app_info['app_dir'] = settings.MEDIA_ROOT / 'upload' / checksum   #APK所在文件夹路径
        app_info['tools_dir'] = app_info['dir'] / 'StaticAnalyzer' / 'tools'
        app_info['tools_dir'] = app_info['tools_dir'].as_posix()
        logger.info('开始分析 : %s' , app_info['app_name'])
        if typ == 'apk':
            app_info['app_file'] = app_info['md5'] + '.apk'  # NEW FILENAME
            app_info['app_path'] = (
                app_info['app_dir'] / app_info['app_file']).as_posix()    #apk文件路径
            app_info['app_dir'] = app_info['app_dir'].as_posix() + '/'
            # unzip_apk_apktool(app_path=app_info['app_path'],app_dir= app_info['app_dir'],tools_dir=app_info['tools_dir'])
                #检查数据库中是否已经有该app的分析数据
            re_db_entry = RecentScansDB.objects.get(MD5=app_info['md5'])

            db_entry = StaticAnalyzerAndroid.objects.filter(
                    MD5=app_info['md5'])
            if db_entry.exists() and rescan == '0':
                    context = get_info_from_db_entry(db_entry)
            else:
                # 开始分析
                app_info['size'] = str(
                    file_size(app_info['app_path'])) + 'MB'  # FILE SIZE
                    # app_info['files'] = unzip(
                    #     app_info['app_path'], app_info['app_dir'])
                app_info['files'] = ['1']
                logger.info('解压APK')
                if not app_info['files']:
                    # Can't Analyze APK, bail out.
                    msg = 'APK file is invalid or corrupt'
                    return print_n_send_error_response(
                                request,
                                msg,
                                False)
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

                # Get icon
                res_path = os.path.join(app_info['app_dir'], 'res')
                app_info['icon_hidden'] = True
                # Even if the icon is hidden, try to guess it by the
                # default paths
                app_info['icon_found'] = False
                app_info['icon_path'] = ''
                    # TODO: Check for possible different names for resource
                    # folder?
                if os.path.exists(res_path):
                    icon_dic = {}
                    # get_icon(
                        # app_info['app_path'], res_path)
                    if icon_dic:
                        app_info['icon_hidden'] = icon_dic['hidden']
                        app_info['icon_found'] = bool(icon_dic['path'])
                        app_info['icon_path'] = icon_dic['path']

                    # Set Manifest link
                app_info['mani'] = ('../manifest_view/?md5='
                                       + app_info['md5']
                                       + '&type=apfk&bin=1')
                
                manifest_data_dict = get_manifest_data(app_info['app_path'])

                manifest_analysis_dict =  manifest_analysis(
                        app_info['parsed_xml'],
                        manifest_data_dict,
                        '',
                        app_info['app_dir'],
                    )
                elf_dict = {'elf_analysis':''}
                # elf_analysis(app_info['app_dir'])

                # apk_2_java(app_info['app_path'], app_info['app_dir'],
                            #    app_info['tools_dir'])

                # dex_2_smali(app_info['app_dir'], app_info['tools_dir'])

                code_an_dic = code_analysis(
                        app_info['app_dir'],
                        'apk',
                        app_info['manifest_file'])

             # Get the strings from android resource and shared objects
                string_res =''
                #  strings_from_apk(
                #         app_info['app_file'],
                #         app_info['app_dir'],
                #         elf_dict['elf_strings'])
                if string_res:
                    app_info['strings'] = string_res['strings']
                    app_info['secrets'] = string_res['secrets']
                    code_an_dic['urls_list'].extend(
                            string_res['urls_list'])
                    code_an_dic['urls'].extend(string_res['url_nf'])
                    code_an_dic['emails'].extend(string_res['emails_nf'])
                else:
                    app_info['strings'] = []
                    app_info['secrets'] = []
                    # Firebase DB Check
                code_an_dic['firebase'] = []
                # firebase_analysis(
                #         list(set(code_an_dic['urls_list'])))
                    # Domain Extraction and Malware Check
                logger.info(
                        'Performing Malware Check on extracted Domains')
                code_an_dic['domains'] =[]
                #  MalwareDomainCheck().scan(
                #         list(set(code_an_dic['urls_list'])))
                    # Copy App icon
                # copy_icon(app_info['md5'], app_info['icon_path'])
                app_info['zipped'] = 'apk'

                logger.info('Connecting to Database')
                try:
                    # SAVE TO DB
                    if rescan == '1':
                        logger.info('Updating Database...')
                        save_or_update(
                                'update',
                                app_info,
                                manifest_data_dict,
                                manifest_analysis_dict,
                                code_an_dic,
                                elf_dict['elf_analysis'],
                            )
                        # update_scan_timestamp(app_info['md5'])
                    elif rescan == '0':
                        logger.info('Saving to Database')
                        # save_or_update(
                        #         'save',
                        #         app_info,
                        #         manifest_data_dict,
                        #         manifest_analysis_dict,
                        #         code_an_dic,
                        #         cert_dic,
                        #         elf_dict['elf_analysis'],
                        #         apkid_results,
                        #         tracker_res,
                        #     )
                except Exception:
                    logger.exception('Saving to Database Failed')
                context = get_info_from_analysis(
                        app_info,
                        manifest_data_dict,
                        manifest_analysis_dict,
                        code_an_dic,
                        elf_dict['elf_analysis'],
                    )
            context['average_cvss'], context['security_score'] = 0,0
                    # score(context['code_analysis'])
            context['dynamic_analysis_done'] = is_file_exists(
                    os.path.join(app_info['app_dir'], 'logcat.txt'))

            context['virus_total'] = None
            # if settings.VT_ENABLED:
            #     vt = VirusTotal.VirusTotal()
            #     context['virus_total'] = vt.get_result(
            #             app_info['app_path'],
            #             app_info['md5'])
            template = 'static_analysis/android_binary_analysis.html'
            return render(request, template, context) 
                # Check if in DB
                # pylint: disable=E1101
                # db_entry = StaticAnalyzerAndroid.objects.filter(
                #     MD5=app_info['md5']).update(PACKAGE_NAME = _apk.get_package(),
                #     VERSION_NAME = _apk.get_androidversion_name(),
                #     APP_NAME = _apk.get_app_name()
                #     )
        logger.info('分析成功 : %s' , app_info['app_name'])
    template = 'static_analysis/android_binary_analysis.html'
    # return render(request, template, context={})
    return HttpResponse(json.dumps('success'))