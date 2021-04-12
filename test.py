from pathlib import Path
import subprocess

import psutil
def find_java_source_folder(base_folder: Path):
    # Find the correct java/kotlin source folder for APK/source zip
    # Returns a Tuple of - (SRC_PATH, SRC_TYPE, SRC_SYNTAX)
    return next(p for p in [(base_folder / 'java_source',
                             'java', '*.java'),
                            (base_folder / 'app' / 'src' / 'main' / 'java',
                             'java', '*.java'),
                            (base_folder / 'app' / 'src' / 'main' / 'kotlin',
                             'kotlin', '*.kt'),
                            (base_folder / 'src',
                             'java', '*.java')])

def b():
    next(i for i in range(10))

if __name__ == '__main__':
    import logging
    logger = logging.getLogger(__name__)
    out = subprocess.check_output(
                ['adb','devices'],
                stderr=subprocess.STDOUT)
    print(out)
    out = out.decode(encoding='utf-8')
    print(out)