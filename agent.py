import argparse
import configparser
import json
import logging
import requests
import sys
import traceback
from datetime import datetime
from pathlib import Path
from time import sleep

from cryptography.fernet import Fernet
from dmidecode import DMIDecode

class Agent:
    def __init__(self, config):
        self.identity = self.get_identity()
        logging.info(f'Initializing with identity {self.identity}')
        self.config = config

    def get_identity(self):
        uuid = None
        try:
            dmi = DMIDecode()
            uuid = dmi.get('System')[0].get('UUID')
        except:
            logging.error('Failed to get system UUID')
            logging.debug(traceback.format_exc())
        return uuid.lower()

    def check_identity(self):
        current_identity = self.get_identity()
        logging.debug(f'Initialized identity: {self.identity}, ' + \
                      f'Current identity: {current_identity}')
        return self.identity == current_identity

    def get_key(self, identity):
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
        self.identity = identity
        return instructions

def load_config(config_file):
    config = configparser.ConfigParser()
    config.read(config_file)
    try:
        return config['AGENT']
    except KeyError:
        logging.critical(f'Failed to read config file from {config_file}')
        sys.exit(1)

def parse_args():
    year = datetime.now().year
    parser = argparse.ArgumentParser(description=f'AIR Agent service (Cumulus Networks © {year})')
    parser.add_argument('-c', '--config-file',
                        help='Location of the service\'s config file ' + \
                             '(default: /etc/cumulus-air/agent.ini)',
                        default='/etc/cumulus-air/agent.ini')
    parser.add_argument('-l', '--log-level', help='Logging verbosity level (default: WARNING)',
                        default='WARNING', choices=('CRITICAL', 'ERROR', 'WARNING', 'INFO',
                                                    'DEBUG'))
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    config = load_config(args.config_file)
    logging.getLogger().setLevel(args.log_level)
    agent = Agent(config)
    while True:
        same_id = agent.check_identity()
        if not same_id:
            logging.info('Identity has changed!')
            instructions = agent.get_instructions()
            print(instructions)
        sleep(int(config['CHECK_INTERVAL']))
