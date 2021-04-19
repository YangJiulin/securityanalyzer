
import psutil
def find_process_by(name):
    """Return a set of process path matching name."""
    proc = set()
    for p in psutil.process_iter(attrs=['name']):
        if (name == p.info['name']):
            proc.add(p.exe())
    return proc

print(find_process_by('adb.exe'))