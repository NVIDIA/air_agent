"""
The AIR Agent is a systemd service that detects if a VM has been cloned.
When a clone operation has been detected, it calls out to the AIR API to see if there are any
post-clone instructions available to execute.
"""

import argparse
import configparser
import glob
import json
import logging
import re
import subprocess
import sys
import traceback
from datetime import datetime, timedelta
from pathlib import Path
from time import sleep

from cryptography.fernet import Fernet
import requests

import executors

class Agent:
    """
    Agent daemon
    """
    def __init__(self, config):
        self.config = config
        self.clock = datetime.now()
        self.identity = self.get_identity()
        logging.info(f'Initializing with identity {self.identity} at {self.clock}')
        parse_instructions(self)

    def get_identity(self):
        """
        Gets the VM's identity (UUID) via its key drive

        Returns:
        str - The VM UUID (ex: 'abcdefab-0000-1111-2222-123456789012')
        """
        key_dir = self.config['KEY_DIR']
        try:
            subprocess.run(f'umount {key_dir} 2>/dev/null', shell=True)
        except subprocess.CalledProcessError:
            logging.debug(f'{key_dir} is not mounted')
        try:
            subprocess.run(f'mount -a 2>/dev/null', shell=True)
        except:
            logging.error(f'Failed to refresh {key_dir}')
            logging.debug(traceback.format_exc())
            return None
        uuid_path = glob.glob(f'{key_dir}uuid*.txt')
        if bool(len(uuid_path)):
            uuid_path = uuid_path[0]
            logging.debug(f'Checking for identity at {uuid_path}')
            with open(uuid_path) as uuid_file:
                return uuid_file.read().strip().lower()
        else:
            logging.error(f'Failed to find identity file')
            return None

    def check_identity(self):
        """
        Checks the VM's current identity against its initialized identity

        Returns:
        bool - True if the VM's identity is still the same
        """
        current_identity = self.get_identity()
        logging.debug(f'Initialized identity: {self.identity}, ' + \
                      f'Current identity: {current_identity}')
        return self.identity == current_identity

    def get_key(self, identity):
        """
        Fetch's the VM's decryption key from its key drive

        Arguments:
        identity (str) - The VM's current UUID. This is used to validate we have the correct
                         key file.

        Returns:
        str - The decryption key
        """
        logging.debug(f'Getting key for {identity}')
        filename = identity.split('-')[0]
        key_dir = self.config['KEY_DIR']
        key_path = f'{key_dir}{filename}.txt'
        logging.debug(f'Checking for key at {key_path}')
        if Path(key_path).is_file():
            with open(key_path) as key_file:
                return key_file.read().strip()
        else:
            logging.error(f'Failed to find decryption key for {identity}')
            return None

    def decrypt_instructions(self, instructions, identity):
        """
        Decrypts a set of instructions received from the AIR API

        Arguments:
        instructions (list) - A list of encrypted instructions received from the API
        identity (str) - The VM's current UUID

        Returns:
        list - A list of decrypted instructions
        """
        decrypted_instructions = []
        key = self.get_key(identity)
        if key:
            logging.debug('Decrypting post-clone instructions')
            crypto = Fernet(key)
            for instruction in instructions:
                clear_text = crypto.decrypt(bytes(instruction['instruction'], 'utf-8'))
                decrypted_instructions.append(json.loads(clear_text))
        return decrypted_instructions

    def get_instructions(self):
        """
        Fetches a set of post-clone instructions from the AIR API

        Returns:
        list - A list of instructions
        """
        logging.debug('Getting post-clone instructions')
        identity = self.get_identity()
        url = self.config['AIR_API']
        url += f'simulation-node/{identity}/instructions/'
        try:
            res = requests.get(url)
            instructions = res.json()
        except:
            logging.error('Failed to get post-clone instructions')
            logging.debug(traceback.format_exc())
            return {}
        instructions = self.decrypt_instructions(instructions, identity)
        return instructions

    def delete_instructions(self):
        """
        Deletes instructions via the AIR API. This serves as an indication that the instructions
        have been successfully executed (i.e. they do not need to be re-tried)
        """
        logging.debug('Deleting post-clone instructions')
        url = self.config['AIR_API']
        url += f'simulation-node/{self.identity}/instructions/'
        try:
            requests.delete(url)
        except:
            logging.error('Failed to delete post-clone instructions')
            logging.debug(traceback.format_exc())

    def clock_jumped(self):
        """
        Returns True if the system's time has jumped by +/- 5 minutes since the last recorded time
        """
        now = datetime.now()
        delta = now - self.clock
        logging.debug(f'Last run: {self.clock}, Now: {now}, Delta: {delta}')
        return (delta > timedelta(minutes=5)) or (-delta > timedelta(minutes=5))

    def fix_clock(self):
        """
        Fixes the system's time by 1) syncing the clock from the hypervisor, and
        2) Restarting any running NTP/chrony service
        """
        try:
            logging.info('Syncing clock from hypervisor')
            subprocess.run('hwclock -s', shell=True) # sync from hardware
            restart_ntp()
            self.clock = datetime.now()
        except:
            logging.debug(traceback.format_exc())
            logging.error('Failed to fix clock')

def load_config(config_file):
    """
    Helper function to load the agent's config file

    Arguments:
    config_file (str) - The fully qualified path to the agent configuration file

    Returns:
    dict - A dictionary of all loaded config values
    """
    config = configparser.ConfigParser()
    config.read(config_file)
    try:
        return config['AGENT']
    except KeyError:
        logging.critical(f'Failed to read config file from {config_file}')
        sys.exit(1)

def parse_args():
    """
    Helper function to provide command line arguments for the agent
    """
    year = datetime.now().year
    parser = argparse.ArgumentParser(description=f'AIR Agent service (Cumulus Networks © {year})')
    parser.add_argument('-c', '--config-file',
                        help='Location of the service\'s config file ' + \
                             '(default: /etc/cumulus-air/agent.ini)',
                        default='/etc/cumulus-air/agent.ini')
    return parser.parse_args()

def parse_instructions(agent):
    """
    Parses and executes a set of instructions from the AIR API

    Arguments:
    agent (Agent) - An Agent instance
    """
    results = []
    instructions = agent.get_instructions()
    for instruction in instructions:
        executor = instruction['executor']
        if executor in executors.EXECUTOR_MAP.keys():
            results.append(executors.EXECUTOR_MAP[executor](instruction['data']))
        else:
            logging.warning(f'Received unsupported executor {executor}')
    if len(results) > 0 and all(results):
        agent.delete_instructions()
        agent.identity = agent.get_identity()

def restart_ntp():
    """
    Restarts any running ntpd or chrony service that might be running. Includes support for
    services running in a VRF.
    """
    services = subprocess.check_output('systemctl list-units -t service --plain --no-legend',
                                       shell=True)
    for line in services.decode('utf-8').split('\n'):
        service = line.split(' ')[0]
        if re.match(r'(ntp|chrony).*\.service', service):
            logging.info(f'Restarting {service}')
            subprocess.call(f'systemctl restart {service}', shell=True)

def start_daemon(agent, test=False):
    """
    Main worker function. Starts an infinite loop that periodically checks its identity and,
    if changed, asks the API for post-clone instructions.

    Arguments:
    agent (Agent) - An Agent instance
    [test] (bool) - Used in unit testing to avoid infinite loop
    """
    while True:
        if agent.clock_jumped():
            agent.fix_clock()
        same_id = agent.check_identity()
        if not same_id:
            logging.info('Identity has changed!')
            parse_instructions(agent)

        sleep(int(agent.config['CHECK_INTERVAL']))
        if test:
            break

if __name__ == '__main__':
    ARGS = parse_args()
    CONFIG = load_config(ARGS.config_file)
    LOG_LEVEL = 'WARNING'
    if CONFIG['LOG_LEVEL'].upper() in ('CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG'):
        LOG_LEVEL = CONFIG['LOG_LEVEL'].upper()
    logging.getLogger().setLevel(LOG_LEVEL)
    AGENT = Agent(CONFIG)

    start_daemon(AGENT)
