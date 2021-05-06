# from pathlib import Path,PurePath
# import subprocess

# import psutil
# def find_java_source_folder(base_folder: Path):
#     # Find the correct java/kotlin source folder for APK/source zip
#     # Returns a Tuple of - (SRC_PATH, SRC_TYPE, SRC_SYNTAX)
#     return next(p for p in [(base_folder / 'java_source',
#                              'java', '*.java'),
#                             (base_folder / 'app' / 'src' / 'main' / 'java',
#                              'java', '*.java'),
#                             (base_folder / 'app' / 'src' / 'main' / 'kotlin',
#                              'kotlin', '*.kt'),
#                             (base_folder / 'src',
#                              'java', '*.java')])

# def b():
#     next(i for i in range(10))

# if __name__ == '__main__':
#     import os
from os import read
import frida, sys

def on_message(message, data):
    print(message)

jscode = """
Java.perform(function () {
    send("init");
    const Activity = Java.use('com.projectkr.shell.MainActivity');
    const Exception = Java.use('java.lang.Exception');
    Activity.onResume.implementation = function (args) {
        send("启动了APP");
        console.log(args);
        this.onResume();
  };
});
"""

# Find Frida server on USB Device (Mobile)
devices = frida.get_usb_device()
# Open APP On Pause State And Attach To It
pid = devices.spawn(['Han.GJZS'])
# Load Script And Add Message Callback
session = devices.attach(pid)
# script = session.create_script(open('test.js').read())
script = session.create_script(jscode)
script.on('message', on_message)
script.load()
# Resume App
devices.resume(pid)
# Wait For User Input To End The Script
# input('Press enter to continue...')
sys.stdin.read()
# script.unload()
# session.detach()