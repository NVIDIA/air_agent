"""
Platform detection functions
"""

import logging
import subprocess
import traceback

def detect():
    """
    Detect the current platform
    """
    os = None
    release = None
    try:
        os = subprocess.run(['lsb_release', '-i'], check=True, stdout=subprocess.PIPE)
        os = os.stdout.decode().split('\t')[1].rstrip()
        try:
            release = subprocess.run(['lsb_release', '-r'], check=True, stdout=subprocess.PIPE)
            release = release.stdout.decode().split('\t')[1].rstrip()
        except:
            logging.debug(traceback.format_exc())
            logging.warning('Platform detection failed to determine Release')
    except:
        logging.debug(traceback.format_exc())
        logging.warning('Platform detection failed to determine OS')
    logging.debug(f'Detected OS: {os} and Release: {release}')
    return os, release
