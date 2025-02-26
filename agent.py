# SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
The NVIDIA Air Agent is a systemd service that detects if a VM has been cloned.
When a clone operation has been detected, it calls out to the Air API to see if there are any
post-clone instructions available to execute.
"""

import argparse
import glob
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import traceback
import typing
from datetime import datetime, timedelta
from pathlib import Path
from time import sleep

import git
import requests
from cryptography.fernet import Fernet

import executors
import platform_detect
from config import Config
from version import AGENT_VERSION

KEY_DEVICE_VOLUME_ID_CONFIG_VAR = 'KEY_DEVICE_VOLUME_ID'
KEY_DEVICE_VOLUME_ID_DEFAULT = 'airagent'
KEY_DEVICE_FALLBACK_PATH_CONFIG_VAR = 'KEY_DEVICE'
KEY_DEVICE_FALLBACK_PATH_DEFAULT = '/dev/vdb'
KEY_DIR_CONFIG_VAR = 'KEY_DIR'
KEY_DIR_DEFAULT = '/mnt/air/'


class Agent:
    """
    Agent daemon
    """

    def __init__(self, config):
        self.config = config
        self.config['AIR_API'] = self.config['AIR_API'].replace('cumulusnetworks.com', 'nvidia.com')
        self.identity = self.get_identity()
        self.lock = threading.Lock()
        self.monitoring = False
        self.hwclock_switch = None
        self.verify_ssl = self.config.getboolean('VERIFY_SSL', True)
        self.set_hwclock_switch()
        fix_clock()
        self.auto_update()
        logging.info(f'Initializing with identity {self.identity}')
        self.os, self.release = platform_detect.detect()

    def unlock(self):
        """Unlocks the agent lock if locked"""
        try:
            self.lock.release()
        except RuntimeError:
            pass

    def set_hwclock_switch(self):
        """
        Detects util-linux's hwclock version. Versions >= 2.32 should use --verbose
        when reading the hardware clock. Older versions should use --debug.

        Returns:
        str - The appropriate switch to use. Defaults to --debug.
        """
        try:
            output = subprocess.check_output('hwclock --version', shell=True)
            match = re.match(r'.*(\d+\.\d+\.\d+)', output.decode('utf-8'))
            version = match.groups()[0]
            if version >= '2.32':
                logging.debug('Detected hwclock switch: --verbose')
                self.hwclock_switch = '--verbose'
                return
        except Exception:
            logging.debug(traceback.format_exc())
            logging.info('Failed to detect hwclock switch, falling back to --debug')
        logging.debug('Detected hwclock switch: --debug')
        self.hwclock_switch = '--debug'

    def get_identity(self):
        """
        Gets the VM's identity (UUID) via its key drive

        Returns:
        str - The VM UUID (ex: 'abcdefab-0000-1111-2222-123456789012')
        """
        key_dir = get_key_directory_path(self.config)

        if not mount_device(self.config):
            logging.error(f'Failed to refresh {key_dir}')
            logging.debug(traceback.format_exc())
            return None
        uuid_path = glob.glob(str(key_dir / 'uuid*.txt'))
        if uuid_path:
            uuid_path = uuid_path[0]
            logging.debug(f'Checking for identity at {uuid_path}')
            with open(uuid_path) as uuid_file:
                return uuid_file.read().strip().lower()
        else:
            logging.error('Failed to find identity file')
            return None

    def check_identity(self):
        """
        Checks the VM's current identity against its initialized identity

        Returns:
        bool - True if the VM's identity is still the same
        """
        current_identity = self.get_identity()
        logging.debug(f'Initialized identity: {self.identity}, ' + f'Current identity: {current_identity}')
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
        key_dir = get_key_directory_path(self.config)
        key_path = key_dir / '.'.join((filename, 'txt'))
        logging.debug(f'Checking for key at {key_path}')
        if key_path.is_file():
            with key_path.open() as key_file:
                return key_file.read().strip()
        else:
            logging.error(f'Failed to find decryption key for {identity}')
            return None

    def decrypt_instructions(self, instructions, identity):
        """
        Decrypts a set of instructions received from the Air API

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
        Fetches a set of post-clone instructions from the Air API

        Returns:
        list - A list of instructions on success, or False if an error occurred
        """
        logging.debug('Getting post-clone instructions')
        identity = self.get_identity()
        url = self.config['AIR_API']
        url += f'simulation-node/{identity}/instructions/'
        try:
            if not identity:
                raise Exception('No identity')
            res = requests.get(url, timeout=10, verify=self.verify_ssl)
            instructions = res.json()
            logging.debug(f'Encrypted instructions: {instructions}')
        except:
            logging.error('Failed to get post-clone instructions')
            logging.debug(traceback.format_exc())
            return False
        instructions = self.decrypt_instructions(instructions, identity)
        logging.debug(f'Decrypted instructions: {instructions}')
        return instructions

    def delete_instructions(self):
        """
        Deletes instructions via the Air API. This serves as an indication that the instructions
        have been successfully executed (i.e. they do not need to be re-tried)
        """
        logging.debug('Deleting post-clone instructions')
        url = self.config['AIR_API']
        url += f'simulation-node/{self.identity}/instructions/'
        try:
            requests.delete(url, verify=self.verify_ssl)
        except:
            logging.error('Failed to delete post-clone instructions')
            logging.debug(traceback.format_exc())

    def signal_watch(self, attempt=1, test=False):
        """
        Waits for a signal from the Air Worker and proceeds accordingly. This runs in a loop
        so it is intended to be executed in a separate thread.

        Arguments:
        attempt [int] - The attempt number used for retries
        test [bool] - Used for CI testing to avoid infinite loops (default: False)
        """
        try:
            channel = open(self.config['CHANNEL_PATH'], 'wb+', buffering=0)
            logging.debug(f'Opened channel path {self.config["CHANNEL_PATH"]}')
            while True:
                data = channel.readline().decode('utf-8')
                logging.debug(f'Got signal data {data}')
                signal = ''
                if data:
                    (timestamp, signal) = data.split(':')
                if signal == 'checkinst\n':
                    logging.debug('signal_watch :: Checking for instructions')
                    res = parse_instructions(self, channel=channel)
                    if res:
                        logging.debug('Channel success')
                        channel.write(f'{timestamp}:success\n'.encode('utf-8'))
                    else:
                        logging.debug('Channel error')
                        channel.write(f'{timestamp}:error\n'.encode('utf-8'))
                elif signal.startswith('resize'):
                    _, rows, cols = signal.strip('\n').split('_')
                    logging.debug(f'resizing serial console: {rows}x{cols}')
                    subprocess.run(['stty', '-F', '/dev/ttyS0', 'rows', str(rows)], check=False)
                    subprocess.run(['stty', '-F', '/dev/ttyS0', 'cols', str(cols)], check=False)
                sleep(1)
                if test:
                    break
        except Exception as err:
            try:
                channel.close()
            except Exception:
                pass
            logging.debug(traceback.format_exc())
            if attempt <= 3:
                backoff = attempt * 10
                logging.warning(
                    f'signal_watch :: {err} (attempt #{attempt}). ' + f'Trying again in {backoff} seconds...'
                )
                sleep(backoff)
                self.signal_watch(attempt + 1, test=test)
            else:
                logging.error(f'signal_watch :: {err}. Ending thread.')

    def monitor(self, channel, test=False, **kwargs):
        """
        Worker target for a monitor thread. Writes any matching updates to the channel.

        Arguments:
        channel (fd) - Comm channel with worker
        test [bool] - If True, the monitor loop ends after 1 iteration (used for unit testing)
        **kwargs (dict) - Required:
                           - file: full path of the file to monitor
                           - pattern: regex that should be considered a match for a progress update
        """
        filename = kwargs.get('file')
        if not filename:
            return
        pattern = kwargs.get('pattern')
        logging.info(f'Starting monitor for {filename}')
        while self.monitoring and not os.path.exists(filename):
            time.sleep(1)
        with open(filename, 'r') as monitor_file:
            while self.monitoring:
                line = monitor_file.readline()
                if line:
                    logging.debug(f'monitor :: {line}')
                    match = re.match(pattern, line)
                    if match and match.groups():
                        logging.debug(f'monitor :: found match {match.groups()[0]}')
                        channel.write(f'{int(time.time())}:{match.groups()[0]}\n'.encode('utf-8'))
                        time.sleep(0.5)
                if test:
                    break
            logging.info(f'Stopping monitor for {filename}')

    def clock_jumped(self):
        """
        Returns True if the system's time has drifted by +/- 30 seconds from the hardware clock
        """
        system_time = datetime.now()
        try:
            cmd = f'hwclock {self.hwclock_switch} | grep "Hw clock"'
            hwclock_output = subprocess.check_output(cmd, shell=True)
            match = re.match(r'.* (\d+) seconds since 1969', hwclock_output.decode('utf-8'))
            if match:
                hw_time = datetime.fromtimestamp(int(match.groups()[0]))
            else:
                raise Exception('Unable to parse hardware clock')
        except:
            logging.debug(traceback.format_exc())
            hw_time = datetime.fromtimestamp(0)
            logging.warning('Something went wrong. Syncing clock to be safe...')
        delta = system_time - hw_time
        logging.debug(f'System time: {system_time}, Hardware time: {hw_time}, Delta: {delta}')
        return (delta > timedelta(seconds=30)) or (-delta > timedelta(seconds=30))

    def auto_update(self):
        """Checks for and applies new agent updates if available"""
        if not self.config.getboolean('AUTO_UPDATE'):
            logging.debug('Auto update is disabled')
            return
        logging.info('Checking for updates')
        try:
            res = requests.get(self.config['VERSION_URL'])
            # pylint: disable=invalid-string-quote
            latest = res.text.split(' = ')[1].strip().strip("'")
            if AGENT_VERSION != latest:
                logging.debug('New version is available')
            else:
                logging.debug('Already running the latest version')
                return
        except Exception as err:
            logging.debug(traceback.format_exc())
            logging.error(f'Failed to check for updates: {err}')
            return
        logging.info('Updating agent')
        try:
            shutil.rmtree('/tmp/air-agent')
        except Exception:
            pass
        try:
            git.Repo.clone_from(self.config['GIT_URL'], '/tmp/air-agent', branch=self.config['GIT_BRANCH'])
            cwd = os.getcwd()
            for filename in os.listdir('/tmp/air-agent'):
                if '.py' in filename:
                    shutil.move(f'/tmp/air-agent/{filename}', f'{cwd}/{filename}')
        except Exception as err:
            logging.debug(traceback.format_exc())
            logging.error(f'Failed to update agent: {err}')
            return
        logging.info('Restarting agent')
        os.execv(sys.executable, ['python3'] + sys.argv)

    def clock_watch(self, **kwargs):
        """
        Watches for clock jumps and updates the clock
        """
        logging.debug('Starting clock watch thread')
        while True:
            wait = self.config.getint('CHECK_INTERVAL')
            if self.clock_jumped():
                fix_clock()
                wait += 300
            sleep(wait)
            if kwargs.get('test'):
                break


def parse_args():
    """
    Helper function to provide command line arguments for the agent
    """
    default_config_file = str(Path(KEY_DIR_DEFAULT, 'agent.ini'))
    year = datetime.now().year
    parser = argparse.ArgumentParser(description=f'Air Agent service (NVIDIA © {year})')
    parser.add_argument(
        '-c',
        '--config-file',
        help="Location of the service's config file. "
        + 'Normally this will be injected automatically by the Air platform '
        + f'(default: {default_config_file})',
        default=default_config_file,
    )
    return parser.parse_args()


def parse_instructions(agent, attempt=1, channel=None, lock=True):
    """
    Parses and executes a set of instructions from the Air API

    Arguments:
    agent (Agent) - An Agent instance
    attempt [int] - The attempt number used for retries
    channel [fd] - Comm channel to the worker
    lock [bool] - Block the agent instance from performing other operations
    """
    if lock:
        agent.lock.acquire()
    results = []
    backoff = attempt * 10
    instructions = agent.get_instructions()
    if instructions == []:
        logging.info('Received no instructions')
        agent.identity = agent.get_identity()
        agent.unlock()
        return True
    if instructions is False and attempt <= 10:
        logging.warning(
            f'Failed to fetch instructions on attempt #{attempt}. Retrying in {backoff} seconds...'
        )
        sleep(backoff)
        return parse_instructions(agent, attempt + 1, channel, lock=False)
    if instructions is False:
        logging.error('Failed to fetch instructions. Giving up.')
        agent.unlock()
        return False
    for instruction in instructions:
        executor = instruction['executor']
        if executor == 'init' and not agent.os:
            logging.debug('Skipping init instructions due to missing os')
            continue
        if instruction.get('monitor'):
            agent.monitoring = True
            threading.Thread(
                target=agent.monitor, args=(channel,), kwargs=json.loads(instruction['monitor'])
            ).start()
        if executor in executors.EXECUTOR_MAP.keys():
            results.append(executors.EXECUTOR_MAP[executor](instruction['data']))
        else:
            logging.warning(f'Received unsupported executor {executor}')
        agent.monitoring = False
    if results and all(results):
        logging.debug('All instructions executed successfully')
        agent.identity = agent.get_identity()
        agent.delete_instructions()
        agent.unlock()
        return True
    if results and attempt <= 3:
        logging.warning(
            f'Failed to execute all instructions on attempt #{attempt}. '
            + f'Retrying in {backoff} seconds...'
        )
        sleep(backoff)
        return parse_instructions(agent, attempt + 1, channel, lock=False)
    if results:
        logging.error('Failed to execute all instructions. Giving up.')
    agent.unlock()
    return False


def restart_ntp():
    """
    Restarts any running ntpd or chrony service that might be running. Includes support for
    services running in a VRF.
    """
    services = subprocess.check_output('systemctl list-units -t service --plain --no-legend', shell=True)
    for line in services.decode('utf-8').split('\n'):
        service = line.split(' ')[0]
        if re.match(r'(ntp|chrony).*\.service', service):
            logging.info(f'Restarting {service}')
            subprocess.call(f'systemctl restart {service}', shell=True)


def fix_clock():
    """
    Fixes the system's time by 1) syncing the clock from the hypervisor, and
    2) Restarting any running NTP/chrony service
    """
    try:
        logging.info('Syncing clock from hypervisor')
        subprocess.run('hwclock -s', shell=True)  # sync from hardware
        restart_ntp()
    except:
        logging.debug(traceback.format_exc())
        logging.error('Failed to fix clock')


def start_daemon(agent, test=False):
    """
    Main worker function. Starts an infinite loop that periodically checks its identity and,
    if changed, asks the API for post-clone instructions.

    Arguments:
    agent (Agent) - An Agent instance
    [test] (bool) - Used in unit testing to avoid infinite loop
    """
    threading.Thread(target=agent.clock_watch).start()
    parse_instructions(agent)  # do an initial check for instructions
    threading.Thread(target=agent.signal_watch).start()
    while True:
        same_id = agent.check_identity()
        if not same_id:
            logging.info('Identity has changed!')
            fix_clock()
            agent.auto_update()
            parse_instructions(agent)

        sleep(agent.config.getint('CHECK_INTERVAL'))
        if test:
            break


def get_key_device_path(config: Config) -> Path:
    """
    Resolves path to the key device by looking it up by volume ID and falling back to a default path
    """
    volume_id = typing.cast(str, config.get(KEY_DEVICE_VOLUME_ID_CONFIG_VAR, KEY_DEVICE_VOLUME_ID_DEFAULT))
    key_device_path_fallback = typing.cast(
        str, config.get(KEY_DEVICE_FALLBACK_PATH_CONFIG_VAR, KEY_DEVICE_FALLBACK_PATH_DEFAULT)
    )

    try:
        return Path(
            subprocess.run(
                ('blkid', '--label', volume_id), text=True, check=True, capture_output=True
            ).stdout.strip()
        )
    except subprocess.CalledProcessError:
        logging.warning(
            'Key device with ID `%s` was not found, falling back to `%s`', volume_id, key_device_path_fallback
        )
    except Exception as e:
        logging.warning(
            'An unexpected error has occurred while looking up a key device by ID `%s`, falling back to `%s`: %s',
            volume_id,
            key_device_path_fallback,
            e,
        )

    return Path(key_device_path_fallback)


def get_key_directory_path(config: Config) -> Path:
    """
    Resolves key device mount path from given config with a fallback to a default path
    """
    return Path(typing.cast(str, config.get(KEY_DIR_CONFIG_VAR, KEY_DIR_DEFAULT)))


def check_devices(config):
    """
    Tests for the presence of the key device. If it exists, allow the agent to continue. If it does not
    exist, then exit with a success code so the service doesn't fail, but do not start the daemon thread
    """
    device = get_key_device_path(config)
    key_dir = get_key_directory_path(config)

    if not device.exists():
        logging.info(f'{device} does not exist - agent will not be started')
        return False
    if not mount_device(config):
        return False
    try:
        subprocess.run(f'ls {key_dir / "uuid*"}', shell=True)
    except:
        logging.info(f'Failed to find expected files on {device} filesystem - agent will not be started')
        logging.debug(traceback.format_exc())
        return False

    return True


def mount_device(config):
    """
    Mounts key device to the directory specified in the config file. Unmounts the directory before attempting
    the mount to refresh the contents in the event this node was cloned.
    """
    device = get_key_device_path(config)
    key_dir = get_key_directory_path(config)

    if not key_dir.exists():
        logging.debug(f'{key_dir} does not exist, creating')
        try:
            os.makedirs(str(key_dir))
        except:
            logging.error(f'Failed to create the {key_dir} directory')
            logging.debug(traceback.format_exc())
            return False
    else:
        try:
            subprocess.run(f'umount {key_dir} 2>/dev/null', shell=True)
        except subprocess.CalledProcessError:
            logging.debug(f'{key_dir} exists but is not mounted')
    try:
        subprocess.run(f'mount {device} {key_dir} 2>/dev/null', shell=True)
    except:
        logging.error(f'Failed to mount {device} to {key_dir}')
        logging.debug(traceback.format_exc())
        return False

    return True


if __name__ == '__main__':
    ARGS = parse_args()
    CONFIG = Config(ARGS.config_file)
    if check_devices(CONFIG):
        CONFIG = Config(ARGS.config_file)  # reload config in case key_dir was remounted
        AGENT = Agent(CONFIG)
        logging.info(f'Starting Air Agent daemon v{AGENT_VERSION}')
        start_daemon(AGENT)
    # the necessary filesystem was not present or config files were missing,
    # exit with a success code so the service does not fail
    logging.critical('The agent was not started because the necessary files were not found!')
    sys.exit(0)
