"""
Executor functions for post-clone instructions
"""

import logging
import subprocess
import traceback

def shell(instructions):
    """
    Executor for shell commands

    Arguments:
    instructions (list) - A list of '\n' delimited commands to execute in the system's default shell

    Returns:
    bool - True if all commands executed successfully
    """
    for line in instructions.split('\n'):
        logging.debug(f'EXEC shell :: {line}')
        try:
            subprocess.run(line, shell=True, check=True)
        except:
            logging.error(f'Command `{line}` failed')
            logging.debug(traceback.format_exc())
            return False
    return True

EXECUTOR_MAP = {'shell': shell}
