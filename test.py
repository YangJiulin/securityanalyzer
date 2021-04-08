from pathlib import Path
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
    return next(i for i in range(10))

if __name__ == '__main__':
    s = Path(r'E:\VSCode\securityanalyzer\media\upload\09af06a1dbe94dfc58e92d4f12e526c7\java_source\okhttp3\internal\publicsuffix\PublicSuffixDatabase.java').read_text('utf-8', 'ignore')
    print(type(s))