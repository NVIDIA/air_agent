import logging
import subprocess
import traceback

def shell(instructions):
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
