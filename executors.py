"""
Executor functions for post-clone instructions
"""

import json
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
        logging.info(f'EXEC shell :: {line}')
        try:
            subprocess.run(line, shell=True, check=True)
        except:
            logging.error(f'Command `{line}` failed')
            logging.debug(traceback.format_exc())
            return False
    return True

def file(instructions):
    """
    Executor for file transfers

    Arguments:
    instructions (dict) - A dictionary in the form of {'filename': 'contents', 'post_cmd': ['cmd']}

    Returns:
    bool - True if all files were copied and all post_cmds were executed successfully
    """
    success = True
    post_cmd = []
    try:
        json_data = json.loads(instructions)
    except json.decoder.JSONDecodeError as err:
        logging.error(f'Failed to decode instructions as JSON: {err}')
        return False

    if 'post_cmd' in json_data.keys():
        post_cmd = json_data.pop('post_cmd')
    for filename, content in json_data.items():
        logging.info(f'EXEC file :: writing {filename}')
        logging.debug(content)
        try:
            with open(filename, 'w') as outfile:
                outfile.write(content)
        except:
            logging.debug(traceback.format_exc())
            logging.error(f'Failed to write {filename}')
            success = False
    for cmd in post_cmd:
        logging.info(f'EXEC file :: {cmd}')
        try:
            subprocess.run(cmd, shell=True, check=True)
        except:
            logging.debug(traceback.format_exc())
            logging.error(f'post_cmd `{cmd}` failed')
            success = False
    return success

EXECUTOR_MAP = {'file': file, 'shell': shell}
