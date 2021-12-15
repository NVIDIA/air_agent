"""
Platform detection functions
"""

import logging
import subprocess

def detect():
    """
    Detect the current platform
    """
    os = None
    release = None
    try:
        os = subprocess.run(['lsb_release', '-i'], check=True,
                            stdout=subprocess.STDOUT).stdout.decode().split('\t')[1].rstrip()
        try:
            release = subprocess.run(['lsb_release', '-r'], check=True,
                                     stdout=subprocess.STDOUT).stdout.decode()\
                                     .split('\t')[1].rstrip()
        except:
            logging.warning('Platform detection failed to determine Release')
    except:
        logging.warning('Platform detection failed to determine OS')
    logging.debug(f'Detected OS: {os} and Release: {release}')
    return os, release
