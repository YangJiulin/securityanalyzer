from pathlib import Path,PurePath
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
    import os
    p = Path(__file__)
    print(p)
    print(p / 'tt/')
    print(p / 'tt')
    print(p / '/tt')
    print(os.path.join(p,'tt'))