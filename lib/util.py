import os
import sys
from inspect import currentframe, getframeinfo


def resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


def debug_print(arg):
    frameinfo = getframeinfo(currentframe().f_back)
    print(frameinfo.filename, frameinfo.lineno, ":", arg)
