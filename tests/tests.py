# SPDX-FileCopyrightText: Copyright (c) 2022-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for Agent module
"""
#pylint: disable=unused-argument,missing-class-docstring,missing-function-docstring
#pylint: disable=arguments-differ,no-self-use,too-many-public-methods,too-many-arguments

import json
import subprocess
import sys
import threading
from datetime import datetime
from unittest import TestCase
from unittest.mock import MagicMock, patch

from cryptography.fernet import Fernet

import agent
import executors
import platform_detect
from agent import Agent
from . import util

class TestAgentIdentity(TestCase):
    def setUp(self):
        self.config = util.load_config()

    @patch('subprocess.run')
    @patch('glob.glob', return_value=['./uuid_123.txt'])
    @patch('builtins.open')
    @patch('agent.parse_instructions')
    @patch('agent.fix_clock')
    def test_get_identity(self, mock_fix, mock_parse, mock_open, mock_glob, mock_run):
        mock_file = MagicMock()
        mock_file.read = MagicMock(return_value='ABC\n')
        mock_open.return_value.__enter__.return_value = mock_file
        agent_obj = Agent(self.config)
        res = agent_obj.get_identity()
        key_dir = self.config['KEY_DIR']
        mock_open.assert_called_with(f'{key_dir}uuid_123.txt')
        self.assertEqual(res, 'abc')

    @patch('subprocess.run', side_effect=[True, True, True, subprocess.CalledProcessError(1, 'a'),
                                          True])
    @patch('logging.debug')
    @patch('agent.parse_instructions')
    @patch('agent.fix_clock')
    @patch('agent.platform_detect.detect', return_value=(None, None))
    def test_get_identity_failed_umount(self, mock_detect, mock_fix, mock_parse, mock_log,
                                        mock_run):
        agent_obj = Agent(self.config)
        res = agent_obj.get_identity()
        self.assertIsNone(res)
        key_dir = self.config['KEY_DIR']
        mock_log.assert_called_with(f'{key_dir} is not mounted')

    @patch('subprocess.run', side_effect=[True, True, True, subprocess.CalledProcessError(1, 'a')])
    @patch('logging.error')
    @patch('agent.parse_instructions')
    @patch('agent.fix_clock')
    @patch('agent.platform_detect.detect', return_value=(None, None))
    def test_get_identity_failed_mount(self, mock_detect, mock_fix, mock_parse, mock_log, mock_run):
        agent_obj = Agent(self.config)
        res = agent_obj.get_identity()
        self.assertIsNone(res)
        key_dir = self.config['KEY_DIR']
        mock_log.assert_called_with(f'Failed to refresh {key_dir}')

    @patch('subprocess.run')
    @patch('glob.glob', return_value=[])
    @patch('logging.error')
    @patch('agent.parse_instructions')
    @patch('agent.fix_clock')
    def test_get_identity_no_file(self, mock_fix, mock_parse, mock_log, mock_glob, mock_run):
        agent_obj = Agent(self.config)
        res = agent_obj.get_identity()
        self.assertIsNone(res)
        mock_log.assert_called_with('Failed to find identity file')

class TestAgent(TestCase):
    @patch('agent.parse_instructions')
    @patch('agent.fix_clock')
    def setUp(self, mock_fix, mock_parse):
        self.config = util.load_config()
        self.mock_id = MagicMock(return_value='123-456')
        Agent.get_identity = self.mock_id
        self.agent = Agent(self.config)

    def test_init(self):
        self.assertEqual(self.agent.config, self.config)
        self.mock_id.assert_called()
        self.assertEqual(self.agent.identity, '123-456')
        self.assertFalse(self.agent.monitoring)
        self.assertIsInstance(self.agent.lock, type(threading.Lock()))
        self.assertTrue(self.agent.verify_ssl)

    @patch('agent.parse_instructions')
    @patch('agent.Agent.auto_update')
    @patch('agent.fix_clock')
    def test_init_no_verify_ssl(self, _mock_parse, _mock_update, _mock_fix):
        self.config['VERIFY_SSL'] = 'False'
        test_agent = Agent(self.config)
        self.assertFalse(test_agent.verify_ssl)

    @patch('agent.parse_instructions')
    @patch('agent.Agent.auto_update')
    @patch('agent.fix_clock')
    def test_init_update(self, mock_fix, mock_update, mock_parse):
        Agent(self.config)
        mock_update.assert_called()

    @patch('agent.parse_instructions')
    @patch('agent.Agent.auto_update')
    @patch('agent.fix_clock')
    def test_init_fix_clock(self, mock_fix, mock_update, mock_parse):
        Agent(self.config)
        mock_fix.assert_called()

    @patch('agent.parse_instructions')
    @patch('agent.Agent.auto_update')
    @patch('agent.fix_clock')
    def test_init_redirect(self, _mock_fix, _mock_update, _mock_parse):
        self.config['AIR_API'] = 'http://air.cumulusnetworks.com'
        test_agent = Agent(self.config)
        self.assertEqual(test_agent.config['AIR_API'], 'http://air.nvidia.com')

    def test_check_identity(self):
        res = self.agent.check_identity()
        self.assertTrue(res)
        self.mock_id.return_value = '456'
        res = self.agent.check_identity()
        self.assertFalse(res)

    @patch('agent.Path')
    @patch('builtins.open')
    def test_get_key(self, mock_open, mock_path):
        mock_path.is_file = MagicMock(return_value=True)
        mock_file = MagicMock()
        mock_file.read = MagicMock(return_value='foo\n')
        mock_open.return_value.__enter__.return_value = mock_file
        res = self.agent.get_key('123-456')
        self.assertEqual(res, 'foo')

    @patch('agent.Path')
    @patch('logging.error')
    def test_get_key_failed(self, mock_log, mock_path):
        mock_path.return_value.is_file = MagicMock(return_value=False)
        res = self.agent.get_key('123-456')
        self.assertIsNone(res)
        mock_log.assert_called_with('Failed to find decryption key for 123-456')

    def test_decrypt_instructions(self):
        key = Fernet.generate_key()
        crypto = Fernet(key)
        self.agent.get_key = MagicMock(return_value=key)
        token1 = crypto.encrypt(b'{"instruction": "echo foo"}').decode('utf-8')
        token2 = crypto.encrypt(b'{"instruction": "echo bar"}').decode('utf-8')

        instructions = [{'instruction': token1}, {'instruction': token2}]
        res = self.agent.decrypt_instructions(instructions, '123-456')
        self.assertListEqual(res, [{'instruction': 'echo foo'}, {'instruction': 'echo bar'}])

    @patch('requests.get')
    def test_get_instructions(self, mock_get):
        instructions = {'foo': 'bar'}
        mock_get.json = MagicMock(return_value={'foo': 'encrypted'})
        self.mock_id.return_value = '000-000'
        self.agent.decrypt_instructions = MagicMock(return_value=instructions)
        res = self.agent.get_instructions()
        self.assertEqual(res, instructions)
        url = self.config['AIR_API'] + 'simulation-node/000-000/instructions/'
        mock_get.assert_called_with(url, timeout=10, verify=self.agent.verify_ssl)


    @patch('requests.get', side_effect=Exception)
    @patch('logging.error')
    def test_get_instructions_failed(self, mock_log, mock_get):
        instructions = {'foo': 'bar'}
        mock_get.json = MagicMock(return_value={'foo': 'encrypted'})
        self.mock_id.return_value = '000-000'
        self.agent.decrypt_instructions = MagicMock(return_value=instructions)
        res = self.agent.get_instructions()
        self.assertEqual(res, False)
        mock_log.assert_called_with('Failed to get post-clone instructions')

    @patch('agent.Agent.get_identity', return_value=False)
    @patch('builtins.Exception')
    def test_get_instructions_no_identity(self, mock_exception, mock_identity):
        self.agent.get_instructions()
        mock_exception.assert_called_with('No identity')

    @patch('requests.delete')
    def test_delete_instructions(self, mock_delete):
        url = self.config['AIR_API'] + f'simulation-node/{self.agent.identity}/instructions/'
        self.agent.delete_instructions()
        mock_delete.assert_called_with(url, verify=self.agent.verify_ssl)

    @patch('requests.delete', side_effect=Exception)
    @patch('logging.error')
    def test_delete_instructions_failed(self, mock_log, mock_delete):
        self.agent.delete_instructions()
        mock_log.assert_called_with('Failed to delete post-clone instructions')

    @patch('builtins.open')
    @patch('agent.parse_instructions', return_value=True)
    @patch('agent.sleep')
    def test_signal_watch(self, mock_sleep, mock_parse, mock_open):
        mock_channel = MagicMock()
        mock_channel.readline.return_value = b'123456:checkinst\n'
        mock_open.return_value = mock_channel
        self.agent.signal_watch(test=True)
        mock_open.assert_called_with(self.agent.config['CHANNEL_PATH'], 'wb+', buffering=0)
        mock_channel.readline.assert_called()
        mock_parse.assert_called_with(self.agent, channel=mock_channel)
        mock_channel.write.assert_called_with('123456:success\n'.encode('utf-8'))
        mock_sleep.assert_called_with(1)

    @patch('builtins.open')
    @patch('agent.parse_instructions')
    @patch('agent.sleep')
    def test_signal_watch_unknown_signal(self, mock_sleep, mock_parse, mock_open):
        mock_channel = MagicMock()
        mock_channel.readline.return_value = b'123456:foo\n'
        mock_open.return_value = mock_channel
        self.agent.signal_watch(test=True)
        mock_parse.assert_not_called()
        mock_channel.write.assert_not_called()

    @patch('builtins.open')
    @patch('agent.parse_instructions', return_value=False)
    @patch('agent.sleep')
    def test_signal_watch_error(self, mock_sleep, mock_parse, mock_open):
        mock_channel = MagicMock()
        mock_channel.readline.return_value = b'123456:checkinst\n'
        mock_open.return_value = mock_channel
        self.agent.signal_watch(test=True)
        mock_channel.write.assert_called_with('123456:error\n'.encode('utf-8'))

    @patch('builtins.open', side_effect=Exception('foo'))
    @patch('agent.sleep')
    def test_signal_watch_exception(self, mock_sleep, mock_open):
        self.agent.signal_watch(attempt=3, test=True)
        mock_sleep.assert_called_with(30)

    @patch('builtins.open')
    @patch('time.time', return_value=123456.90)
    @patch('os.path.exists', side_effect=[False, True])
    @patch('time.sleep')
    def test_monitor(self, mock_sleep, mock_exists, mock_time, mock_open):
        mock_file = MagicMock()
        mock_file.readline.return_value = 'bar\n'
        mock_open.return_value.__enter__.return_value = mock_file
        mock_channel = MagicMock()
        self.agent.monitoring = True
        self.agent.monitor(mock_channel, file='/tmp/foo', pattern=r'(bar)', test=True)
        mock_channel.write.assert_called_with('123456:bar\n'.encode('utf-8'))
        mock_sleep.assert_called_with(0.5)
        self.assertEqual(mock_sleep.call_count, 2)

    @patch('builtins.open')
    @patch('time.time', return_value=123456.90)
    @patch('os.path.exists', side_effect=[False, True])
    @patch('time.sleep')
    def test_monitor_no_match(self, mock_sleep, mock_exists, mock_time, mock_open):
        mock_file = MagicMock()
        mock_file.readline.return_value = 'foo\n'
        mock_open.return_value.__enter__.return_value = mock_file
        mock_channel = MagicMock()
        self.agent.monitoring = True
        self.agent.monitor(mock_channel, file='/tmp/foo', pattern=r'(bar)', test=True)
        mock_channel.write.assert_not_called()
        self.assertEqual(mock_sleep.call_count, 1)

    @patch('builtins.open')
    def test_monitor_no_file(self, mock_open):
        self.agent.monitor(MagicMock())
        mock_open.assert_not_called()

    @patch('subprocess.check_output', return_value=b' 10000 seconds since 1969')
    @patch('agent.datetime')
    def test_clock_jumped_past(self, mock_datetime, mock_sub):
        mock_datetime.now = MagicMock(return_value=datetime(2020, 2, 1))
        mock_datetime.fromtimestamp = datetime.fromtimestamp
        res = self.agent.clock_jumped()
        self.assertTrue(res)

    @patch('subprocess.check_output', return_value=b' 99999999999999 seconds since 1969')
    @patch('agent.datetime')
    def test_clock_jumped_future(self, mock_datetime, mock_sub):
        mock_datetime.now = MagicMock(return_value=datetime(2020, 4, 1))
        mock_datetime.fromtimestamp = datetime.fromtimestamp
        res = self.agent.clock_jumped()
        self.assertTrue(res)

    @patch('subprocess.check_output', return_value=b' 1583038800 seconds since 1969')
    @patch('agent.datetime')
    def test_clock_jumped_no_jump(self, mock_datetime, mock_sub):
        mock_datetime.now = MagicMock(return_value=datetime.fromtimestamp(1583038800))
        mock_datetime.fromtimestamp = datetime.fromtimestamp
        res = self.agent.clock_jumped()
        self.assertFalse(res)

    @patch('subprocess.check_output', side_effect=Exception)
    @patch('agent.datetime')
    @patch('logging.warning')
    def test_clock_jumped_exception(self, mock_log, mock_datetime, mock_sub):
        mock_datetime.now = MagicMock(return_value=datetime(2020, 3, 1))
        mock_datetime.fromtimestamp = datetime.fromtimestamp
        res = self.agent.clock_jumped()
        self.assertTrue(res)
        mock_log.assert_called_with('Something went wrong. Syncing clock to be safe...')

    @patch('subprocess.check_output', return_value=b'foo')
    @patch('builtins.Exception')
    def test_clock_jumped_raised(self, mock_exception, mock_sub):
        self.agent.clock_jumped()
        mock_exception.assert_called_with('Unable to parse hardware clock')

    @patch('subprocess.check_output', return_value=b'hwclock from util-linux 2.34.2')
    def test_set_hwclock_switch_new(self, mock_output):
        self.agent.set_hwclock_switch()
        self.assertEqual(self.agent.hwclock_switch, '--verbose')

    @patch('subprocess.check_output', return_value=b'hwclock from util-linux 2.31.1')
    @patch('logging.info')
    def test_set_hwclock_switch_old(self, mock_log, mock_output):
        self.agent.set_hwclock_switch()
        self.assertEqual(self.agent.hwclock_switch, '--debug')
        mock_log.assert_not_called()

    @patch('subprocess.check_output', return_value=b'foo')
    @patch('logging.info')
    def test_set_hwclock_switch_fallback(self, mock_log, mock_output):
        self.agent.set_hwclock_switch()
        self.assertEqual(self.agent.hwclock_switch, '--debug')
        mock_log.assert_called_with('Failed to detect hwclock switch, falling back to --debug')

    @patch('requests.get')
    @patch('logging.debug')
    def test_auto_update_disabled(self, mock_log, mock_get):
        self.agent.auto_update()
        mock_get.assert_not_called()
        mock_log.assert_called_with('Auto update is disabled')

    @patch('requests.get')
    @patch('agent.AGENT_VERSION', '1.4.3')
    @patch('shutil.rmtree')
    @patch('git.Repo.clone_from')
    @patch('os.getcwd', return_value='/tmp/foo')
    @patch('os.listdir', return_value=['test.txt', 'test.py'])
    @patch('shutil.move')
    @patch('os.execv')
    @patch('agent.parse_instructions')
    @patch('agent.fix_clock')
    def test_auto_update(self, mock_fix, mock_parse, mock_exec, mock_move, mock_ls, mock_cwd,
                         mock_clone, mock_rm, mock_get):
        mock_get.return_value.text = 'AGENT_VERSION = \'2.0.0\'\n'
        testagent = Agent(self.config)
        testagent.config['AUTO_UPDATE'] = 'True'
        testagent.auto_update()
        mock_get.assert_called_with(self.config['VERSION_URL'])
        mock_rm.assert_called_with('/tmp/air-agent')
        mock_clone.assert_called_with(self.config['GIT_URL'], '/tmp/air-agent',
                                      branch=self.config['GIT_BRANCH'])
        mock_move.assert_called_with('/tmp/air-agent/test.py', '/tmp/foo/test.py')
        mock_exec.assert_called_with(sys.executable, ['python3'] + sys.argv)

    @patch('requests.get')
    @patch('agent.AGENT_VERSION', '1.4.3')
    @patch('git.Repo.clone_from')
    @patch('agent.parse_instructions')
    @patch('logging.debug')
    @patch('agent.fix_clock')
    def test_auto_update_latest(self, mock_fix, mock_log, mock_parse, mock_clone, mock_get):
        mock_get.return_value.text = 'AGENT_VERSION = \'1.4.3\'\n'
        testagent = Agent(self.config)
        testagent.config['AUTO_UPDATE'] = 'True'
        testagent.auto_update()
        mock_clone.assert_not_called()
        mock_log.assert_called_with('Already running the latest version')

    @patch('requests.get', side_effect=Exception('foo'))
    @patch('agent.AGENT_VERSION', '1.4.3')
    @patch('git.Repo.clone_from')
    @patch('agent.parse_instructions')
    @patch('logging.error')
    @patch('agent.fix_clock')
    def test_auto_update_check_fail(self, mock_fix, mock_log, mock_parse, mock_clone, mock_get):
        testagent = Agent(self.config)
        testagent.config['AUTO_UPDATE'] = 'True'
        testagent.auto_update()
        mock_clone.assert_not_called()
        mock_log.assert_called_with('Failed to check for updates: foo')

    @patch('requests.get')
    @patch('agent.AGENT_VERSION', '1.4.3')
    @patch('shutil.rmtree', side_effect=Exception('foo'))
    @patch('git.Repo.clone_from')
    @patch('os.getcwd', return_value='/tmp/foo')
    @patch('os.listdir', return_value=['test.txt', 'test.py'])
    @patch('shutil.move')
    @patch('os.execv')
    @patch('agent.parse_instructions')
    @patch('agent.fix_clock')
    def test_auto_update_rm_safe(self, mock_fix, mock_parse, mock_exec, mock_move, mock_ls,
                                 mock_cwd, mock_clone, mock_rm, mock_get):
        mock_get.return_value.text = 'AGENT_VERSION = \'2.0.0\'\n'
        testagent = Agent(self.config)
        testagent.config['AUTO_UPDATE'] = 'True'
        testagent.auto_update()
        mock_get.assert_called_with(self.config['VERSION_URL'])
        mock_rm.assert_called_with('/tmp/air-agent')
        mock_clone.assert_called_with(self.config['GIT_URL'], '/tmp/air-agent',
                                      branch=self.config['GIT_BRANCH'])
        mock_move.assert_called_with('/tmp/air-agent/test.py', '/tmp/foo/test.py')
        mock_exec.assert_called_with(sys.executable, ['python3'] + sys.argv)

    @patch('requests.get')
    @patch('agent.AGENT_VERSION', '1.4.3')
    @patch('shutil.rmtree')
    @patch('git.Repo.clone_from', side_effect=Exception('foo'))
    @patch('os.getcwd', return_value='/tmp/foo')
    @patch('os.listdir', return_value=['test.txt', 'test.py'])
    @patch('shutil.move')
    @patch('os.execv')
    @patch('agent.parse_instructions')
    @patch('logging.error')
    @patch('agent.fix_clock')
    def test_auto_update_error(self, mock_fix, mock_log, mock_parse, mock_exec, mock_move, mock_ls,
                               mock_cwd, mock_clone, mock_rm, mock_get):
        mock_get.return_value.text = 'AGENT_VERSION = \'2.0.0\'\n'
        testagent = Agent(self.config)
        testagent.config['AUTO_UPDATE'] = 'True'
        testagent.auto_update()
        mock_exec.assert_not_called()
        mock_log.assert_called_with('Failed to update agent: foo')

    @patch('agent.Agent.clock_jumped', return_value=True)
    @patch('agent.fix_clock')
    @patch('agent.sleep')
    def test_clock_watch(self, mock_sleep, mock_fix, mock_jump):
        self.agent.clock_watch(test=True)
        mock_fix.assert_called()
        mock_sleep.assert_called_with(self.agent.config.getint('CHECK_INTERVAL') + 300)

    @patch('agent.Agent.clock_jumped', return_value=False)
    @patch('agent.fix_clock')
    @patch('agent.sleep')
    def test_clock_watch_no_jump(self, mock_sleep, mock_fix, mock_jump):
        self.agent.clock_watch(test=True)
        mock_fix.assert_not_called()
        mock_sleep.assert_called_with(self.agent.config.getint('CHECK_INTERVAL'))

    def test_unlock(self):
        self.agent.lock.acquire()
        self.agent.unlock()
        self.assertFalse(self.agent.lock.locked())

    def test_unlock_pass(self):
        self.agent.unlock()
        self.assertFalse(self.agent.lock.locked())

class TestAgentFunctions(TestCase):
    class MockConfigParser(dict):
        def __init__(self):
            super().__init__()
            self.read = MagicMock()

    def setUp(self):
        self.config = util.load_config()
        self.mock_parse = self.MockConfigParser()

    @patch('configparser.ConfigParser')
    def test_load_config(self, mock_confparse):
        mock_confparse.return_value = self.mock_parse
        self.mock_parse['AGENT'] = self.config
        res = agent.load_config('test.txt')
        self.assertEqual(res, self.config)
        self.mock_parse.read.assert_called_with('test.txt')

    @patch('configparser.ConfigParser')
    @patch('logging.critical')
    @patch('sys.exit')
    def test_load_config_failed(self, mock_exit, mock_log, mock_confparse):
        mock_confparse.return_value = self.mock_parse
        agent.load_config('test.txt')
        mock_log.assert_called_with('Failed to read config file from test.txt')
        mock_exit.assert_called_with(1)

    @patch('argparse.ArgumentParser')
    def test_parse_args(self, mock_argparse):
        mock_parser = MagicMock()
        mock_argparse.return_value = mock_parser
        mock_parser.add_argument = MagicMock()
        mock_parser.parse_args.return_value = 'foo'
        res = agent.parse_args()
        year = datetime.now().year
        mock_argparse.assert_called_with(description='Air Agent service ' + \
                                         f'(NVIDIA © {year})')
        mock_parser.add_argument.assert_called_with('-c', '--config-file',
                                                    help='Location of the service\'s config ' + \
                                                    'file (default: /etc/nvidia-air/agent.ini)',
                                                    default='/etc/nvidia-air/agent.ini')
        self.assertEqual(res, 'foo')

    @patch('agent.executors')
    @patch('agent.sleep')
    @patch('agent.Agent.get_instructions', return_value=[{'data': 'foo', 'executor': 'shell',
                                                          'monitor': None}])
    @patch('threading.Thread')
    @patch('agent.Agent.auto_update')
    @patch('agent.fix_clock')
    def test_start_daemon(self, mock_fix, mock_update, mock_threading, mock_parse, mock_sleep,
                          mock_exec):
        mock_signal_thread = MagicMock()
        mock_clock_thread = MagicMock()
        mock_threading.side_effect = [mock_signal_thread, mock_clock_thread]
        mock_exec.EXECUTOR_MAP = {'shell': MagicMock()}
        Agent.get_identity = MagicMock(return_value='123-456')
        agent_obj = Agent(self.config)
        agent_obj.check_identity = MagicMock(return_value=False)
        agent_obj.delete_instructions = MagicMock()
        agent.start_daemon(agent_obj, test=True)
        mock_exec.EXECUTOR_MAP['shell'].assert_called_with('foo')
        agent_obj.delete_instructions.assert_called()
        mock_sleep.assert_called_with(self.config.getint('CHECK_INTERVAL'))
        mock_for_assert = MagicMock()
        mock_for_assert(target=agent_obj.clock_watch)
        mock_for_assert(target=agent_obj.signal_watch)
        self.assertEqual(mock_threading.mock_calls, mock_for_assert.mock_calls)
        mock_signal_thread.start.assert_called()
        mock_clock_thread.start.assert_called()
        mock_update.assert_called()

    @patch('agent.executors')
    @patch('agent.sleep')
    @patch('agent.parse_instructions')
    @patch('threading.Thread')
    @patch('agent.fix_clock')
    def test_start_daemon_no_change(self, mock_fix, mock_threading, mock_parse, mock_sleep,
                                    mock_exec):
        Agent.get_identity = MagicMock(return_value='123-456')
        agent_obj = Agent(self.config)
        agent_obj.get_instructions = MagicMock()
        agent_obj.check_identity = MagicMock(return_value=True)
        agent.start_daemon(agent_obj, test=True)
        agent_obj.get_instructions.assert_not_called()
        mock_parse.assert_called()

    @patch('agent.executors')
    @patch('agent.sleep')
    @patch('agent.Agent.get_instructions', return_value=[{'data': 'foo', 'executor': 'shell',
                                                          'monitor': None}])
    @patch('threading.Thread')
    @patch('agent.fix_clock')
    def test_start_daemon_command_failed(self, mock_fix, mock_threading, mock_parse, mock_sleep,
                                         mock_exec):
        mock_exec.EXECUTOR_MAP = {'shell': MagicMock(return_value=False)}
        Agent.get_identity = MagicMock(return_value='123-456')
        agent_obj = Agent(self.config)
        agent_obj.check_identity = MagicMock(return_value=False)
        agent_obj.identity = '000-000'
        agent_obj.delete_instructions = MagicMock()
        agent.start_daemon(agent_obj, test=True)
        mock_exec.EXECUTOR_MAP['shell'].assert_called_with('foo')
        agent_obj.delete_instructions.assert_not_called()
        self.assertEqual(agent_obj.identity, '000-000')

    @patch('agent.executors')
    def test_parse_instructions(self, mock_exec):
        mock_exec.EXECUTOR_MAP = {'shell': MagicMock(side_effect=[1, 2])}
        mock_agent = MagicMock()
        mock_agent.get_instructions.return_value = [
            {'executor': 'shell', 'data': 'foo', 'monitor': None},
            {'executor': 'shell', 'data': 'bar', 'monitor': None}
        ]
        mock_agent.delete_instructions = MagicMock()
        mock_agent.identity = 'xzy'
        mock_agent.get_identity = MagicMock(return_value='abc')
        agent.parse_instructions(mock_agent)
        mock_agent.delete_instructions.assert_called()
        mock_for_assert = MagicMock()
        mock_for_assert('foo')
        mock_for_assert('bar')
        self.assertEqual(mock_exec.EXECUTOR_MAP['shell'].mock_calls, mock_for_assert.mock_calls)
        self.assertEqual(mock_agent.identity, 'abc')
        mock_agent.lock.acquire.assert_called()
        mock_agent.unlock.assert_called()

    @patch('agent.executors')
    @patch('logging.warning')
    def test_parse_instructions_unsupported(self, mock_log, mock_exec):
        mock_exec.EXECUTOR_MAP = {'shell': MagicMock(side_effect=[1, 2])}
        mock_agent = MagicMock()
        mock_agent.get_instructions.return_value = [{'executor': 'test', 'data': 'foo',
                                                     'monitor': None}]
        agent.parse_instructions(mock_agent)
        mock_log.assert_called_with('Received unsupported executor test')

    @patch('agent.sleep')
    def test_parse_instructions_retry(self, mock_sleep):
        mock_agent = MagicMock()
        mock_agent.get_instructions.side_effect = [False, []]
        res = agent.parse_instructions(mock_agent, attempt=3)
        mock_sleep.assert_called_with(30)
        self.assertEqual(mock_agent.get_instructions.call_count, 2)
        self.assertTrue(res)
        mock_agent.lock.acquire.assert_called()
        mock_agent.unlock.assert_called()

    @patch('agent.sleep')
    def test_parse_instructions_failed(self, mock_sleep):
        mock_agent = MagicMock()
        mock_agent.get_instructions.side_effect = [False, False]
        res = agent.parse_instructions(mock_agent, attempt=3)
        mock_sleep.assert_called_with(30)
        self.assertEqual(mock_agent.get_instructions.call_count, 2)
        self.assertFalse(res)
        mock_agent.lock.acquire.assert_called()
        mock_agent.unlock.assert_called()

    @patch('agent.executors')
    @patch('logging.warning')
    @patch('agent.sleep')
    def test_parse_instructions_cmd_failed(self, mock_sleep, mock_log, mock_exec):
        mock_exec.EXECUTOR_MAP = {'shell': MagicMock(side_effect=[False, False, True])}
        mock_agent = MagicMock()
        mock_agent.get_instructions.return_value = [{'executor': 'shell', 'data': 'foo',
                                                     'monitor': None}]
        mock_agent.get_identity = MagicMock(return_value='abc')
        agent.parse_instructions(mock_agent)
        assert_logs = MagicMock()
        assert_logs.warning('Failed to execute all instructions on attempt #1. ' + \
                            'Retrying in 10 seconds...')
        assert_logs.warning('Failed to execute all instructions on attempt #2. ' + \
                            'Retrying in 20 seconds...')
        self.assertEqual(mock_log.mock_calls, assert_logs.mock_calls)
        assert_sleep = MagicMock()
        assert_sleep(10)
        assert_sleep(20)
        self.assertEqual(mock_sleep.mock_calls, assert_sleep.mock_calls)
        mock_agent.get_identity.assert_called()
        mock_agent.lock.acquire.assert_called()
        mock_agent.unlock.assert_called()

    @patch('agent.executors')
    @patch('logging.error')
    @patch('agent.sleep')
    def test_parse_instructions_all_cmd_failed(self, mock_sleep, mock_log, mock_exec):
        mock_exec.EXECUTOR_MAP = {'shell': MagicMock(return_value=False)}
        mock_agent = MagicMock()
        mock_agent.get_instructions.return_value = [{'executor': 'shell', 'data': 'foo',
                                                     'monitor': None}]
        mock_agent.get_identity = MagicMock(return_value='abc')
        agent.parse_instructions(mock_agent)
        assert_sleep = MagicMock()
        assert_sleep(10)
        assert_sleep(20)
        assert_sleep(30)
        self.assertEqual(mock_sleep.mock_calls, assert_sleep.mock_calls)
        mock_agent.get_identity.assert_not_called()
        mock_log.assert_called_with('Failed to execute all instructions. Giving up.')
        mock_agent.lock.acquire.assert_called()
        mock_agent.unlock.assert_called()

    @patch('agent.executors')
    @patch('threading.Thread')
    def test_parse_instructions_monitor(self, mock_thread_class, mock_exec):
        mock_thread = MagicMock()
        mock_thread_class.return_value = mock_thread
        monitor_str = '{"file": "/tmp/foo", "pattern": "bar"}'
        mock_exec.EXECUTOR_MAP = {'shell': MagicMock(side_effect=[1, 2])}
        mock_agent = MagicMock()
        mock_agent.get_instructions.return_value = [{'executor': 'shell', 'data': 'foo',
                                                     'monitor': monitor_str}]
        mock_channel = MagicMock()
        agent.parse_instructions(mock_agent, channel=mock_channel)
        mock_thread_class.assert_called_with(target=mock_agent.monitor, args=(mock_channel,),
                                             kwargs=json.loads(monitor_str))
        mock_thread.start.assert_called()
        mock_agent.lock.acquire.assert_called()
        mock_agent.unlock.assert_called()

    def test_parse_instructions_none(self):
        mock_agent = MagicMock()
        mock_agent.identity = 'abc'
        mock_agent.get_instructions = MagicMock(return_value=[])
        mock_agent.get_identity = MagicMock(return_value='foo')
        res = agent.parse_instructions(mock_agent)
        self.assertTrue(res)
        self.assertEqual(mock_agent.identity, 'foo')
        mock_agent.lock.acquire.assert_called()
        mock_agent.unlock.assert_called()

    @patch('agent.executors')
    @patch('logging.debug')
    def test_parse_instructions_os_none(self, mock_log, mock_exec):
        mock_exec.EXECUTOR_MAP = {'init': MagicMock(side_effect=[1, 2])}
        mock_agent = MagicMock()
        mock_agent.get_instructions.return_value = [
            {'executor': 'init', 'data': '{"hostname": "test"}', 'monitor': None}
        ]
        mock_agent.os = None
        agent.parse_instructions(mock_agent)
        mock_log.assert_called_with('Skipping init instructions due to missing os')


    @patch('subprocess.check_output',
           return_value=b'ntp.service\nfoo.service\nntp@mgmt.service\nchrony.service')
    @patch('subprocess.call')
    def test_restart_ntp(self, mock_call, mock_check):
        mock_for_assert = MagicMock()
        mock_for_assert('systemctl restart ntp.service', shell=True)
        mock_for_assert('systemctl restart ntp@mgmt.service', shell=True)
        mock_for_assert('systemctl restart chrony.service', shell=True)
        agent.restart_ntp()
        self.assertEqual(mock_call.mock_calls, mock_for_assert.mock_calls)

    @patch('subprocess.run')
    @patch('agent.restart_ntp')
    @patch('agent.datetime')
    def test_fix_clock(self, mock_datetime, mock_ntp, mock_run):
        mock_datetime.now = MagicMock(return_value=datetime(2020, 3, 2))
        agent.fix_clock()
        mock_run.assert_called_with('hwclock -s', shell=True)
        mock_ntp.assert_called()

    @patch('subprocess.run', side_effect=Exception)
    @patch('logging.error')
    def test_fix_clock_failed(self, mock_log, mock_run):
        agent.fix_clock()
        mock_log.assert_called_with('Failed to fix clock')

class TestExecutors(TestCase):
    @patch('subprocess.run')
    def test_shell(self, mock_run):
        res = executors.shell('foo\nbar')
        self.assertTrue(res)
        self.assertEqual(mock_run.call_count, 2)

    @patch('subprocess.run', side_effect=Exception)
    @patch('logging.error')
    def test_shell_failed(self, mock_log, mock_run):
        res = executors.shell('foo\nbar\n')
        self.assertFalse(res)
        mock_log.assert_called_with('Command `foo` failed')

    @patch('builtins.open')
    @patch('subprocess.run')
    def test_file(self, mock_run, mock_open):
        outfile = MagicMock()
        outfile.write = MagicMock()
        mock_open.return_value.__enter__.return_value = outfile
        res = executors.file('{"/tmp/foo.txt": "bar", "post_cmd": ["cat /tmp/foo.txt"]}')
        self.assertTrue(res)
        mock_open.assert_called_with('/tmp/foo.txt', 'w')
        outfile.write.assert_called_with('bar')
        mock_run.assert_called_with('cat /tmp/foo.txt', shell=True, check=True)

    @patch('builtins.open')
    @patch('subprocess.run')
    def test_file_cmd_string(self, mock_run, mock_open):
        outfile = MagicMock()
        outfile.write = MagicMock()
        mock_open.return_value.__enter__.return_value = outfile
        res = executors.file('{"/tmp/foo.txt": "bar", "post_cmd": "cat /tmp/foo.txt"}')
        self.assertTrue(res)
        mock_open.assert_called_with('/tmp/foo.txt', 'w')
        outfile.write.assert_called_with('bar')
        mock_run.assert_called_with('cat /tmp/foo.txt', shell=True, check=True)

    @patch('builtins.open', side_effect=Exception)
    @patch('logging.error')
    @patch('subprocess.run')
    def test_file_write_failed(self, mock_run, mock_log, mock_open):
        res = executors.file('{"/tmp/foo.txt": "bar", "post_cmd": ["cat /tmp/foo.txt"]}')
        self.assertFalse(res)
        mock_log.assert_called_with('Failed to write /tmp/foo.txt')

    @patch('builtins.open')
    @patch('subprocess.run', side_effect=Exception)
    @patch('logging.error')
    def test_file_cmd_failed(self, mock_log, mock_run, mock_open):
        outfile = MagicMock()
        outfile.write = MagicMock()
        mock_open.return_value.__enter__.return_value = outfile
        res = executors.file('{"/tmp/foo.txt": "bar", "post_cmd": ["cat /tmp/foo.txt"]}')
        self.assertFalse(res)
        mock_log.assert_called_with('post_cmd `cat /tmp/foo.txt` failed')

    @patch('logging.error')
    def test_file_json_parse_failed(self, mock_log):
        data = '{"/tmp/foo.txt": "bar", "post_cmd": [cat /tmp/foo.txt"]}'
        res = executors.file(data)
        self.assertFalse(res)
        mock_log.assert_called_with('Failed to decode instructions as JSON: ' + \
                                    'Expecting value: line 1 column 38 (char 37)')

    @patch('executors.shell')
    def test_init(self, mock_shell):
        res = executors.init('{"hostname": "test"}')
        self.assertTrue(res)

    @patch('logging.error')
    def test_init_json_parse_failed(self, mock_log):
        res = executors.init('string')
        mock_log.assert_called_with('Failed to decode init data as JSON: ' + \
                                    'Expecting value: line 1 column 1 (char 0)')
        self.assertFalse(res)

class TestPlatformDetect(TestCase):
    @patch('subprocess.run')
    def test_detect(self, mock_exec):
        cmd1 = MagicMock()
        cmd1.stdout = b'Distributor ID:\tUbuntu\n'
        cmd2 = MagicMock()
        cmd2.stdout = b'Release:\t20.04\n'
        mock_exec.side_effect = [cmd1, cmd2]
        res = platform_detect.detect()
        self.assertEqual(res, ('Ubuntu', '20.04'))
        mock_for_assert = MagicMock()
        mock_for_assert(['lsb_release', '-i'], check=True, stdout=subprocess.PIPE)
        mock_for_assert(['lsb_release', '-r'], check=True, stdout=subprocess.PIPE)
        self.assertEqual(mock_exec.mock_calls, mock_for_assert.mock_calls)

    @patch('subprocess.run', side_effect=Exception)
    @patch('logging.warning')
    def test_detect_fail_os(self, mock_log, mock_exec):
        os, release = platform_detect.detect()
        mock_log.assert_called_with('Platform detection failed to determine OS')
        self.assertIsNone(os)
        self.assertIsNone(release)

    @patch('subprocess.run')
    @patch('logging.warning')
    def test_detect_fail_release(self, mock_log, mock_exec):
        os_str = b'Ubuntu'
        cmd1 = MagicMock()
        cmd1.stdout = b'Distributor ID:\t' + os_str + b'\n'
        mock_exec.side_effect = [cmd1, Exception]
        os, release = platform_detect.detect()
        mock_log.assert_called_with('Platform detection failed to determine Release')
        self.assertEqual(os, os_str.decode())
        self.assertIsNone(release)
