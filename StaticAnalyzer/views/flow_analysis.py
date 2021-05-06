import json
from logging import Logger
import logging
import os
from pathlib import Path
import platform

from securityanalyzer.utils import find_java_binary, find_process_by, is_dir_exists
import subprocess

logger = logging.getLogger(__name__)

def flow_analysis(app_dir,app_path,tool_dir,target_sdk):
    jaads = os.path.join(tool_dir,'jaadas/jade-0.1.jar')
    config = os.path.join(tool_dir,'jaadas/config/')
    out_dir = os.path.join(app_dir,'flow_out')
    result = {'results':[]}
    try:
        if platform.system() == 'Windows':
            adb_loc = find_process_by('adb.exe')
        else:
            adb_loc = find_process_by('adb')
        platforms = Path(adb_loc.pop()).resolve().parent.parent / 'platforms'
        need_plat = platforms / ('android-'+str(target_sdk))
        now_platforms = None
        for f in platforms.iterdir():
            f = f.resolve().absolute()
            if f.is_dir():
                now_platforms = f
                break
        if not is_dir_exists(need_plat):
            logger.warning('没有找到%s,将设置软链，source为%s',platforms / ('android-'+str(target_sdk)),now_platforms)
            if platform.system() == 'Windows':
                subprocess.check_output(['mklink','/d',need_plat.as_posix(),now_platforms.as_posix()])
            else:
                subprocess.check_output(['ln','-s',now_platforms.as_posix(),need_plat.as_posix()])
        logger.warning('找到%s,开始执行污点分析',need_plat)
        args = [find_java_binary(),
                '-jar',
                jaads,
                'vulnanalysis',
                '-f',
                app_path,
                '-p',
                platforms.as_posix(),
                '-c',
                config,
                '--fastanalysis',
                '-o',
                out_dir
                ]
        logger.info('执行污点分析')
        subprocess.check_output(args)
        mfile = list(Path(out_dir).iterdir())[0]
        if mfile.exists():
            manifest = mfile.read_text('utf-8', 'ignore')
        else:
            manifest = """{"results":[]}"""  
        result = json.loads(manifest)
    except Exception:
        logging.exception('Run Flow Analysis')
    return result
