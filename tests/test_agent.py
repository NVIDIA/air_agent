# SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for Agent module
"""
# pylint: disable=unused-argument,missing-class-docstring,missing-function-docstring
# pylint: disable=arguments-differ,no-self-use,too-many-public-methods,too-many-arguments

import builtins
import json
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock, call, patch

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
    @patch('agent.parse_instructions')
    @patch('agent.fix_clock')
    def test_get_identity(self, *args):
        with patch.object(
            agent, agent.mount_device.__name__, return_value=True
        ) as mock_mount_device, patch.object(
            agent.glob, agent.glob.glob.__name__, return_value=['/mnt/test/uuid_123.txt']
        ) as mock_glob, patch.object(
            agent, agent.get_key_directory_path.__name__, return_value=Path('/mnt/test/')
        ) as mock_get_key_directory_path, patch.object(
            builtins,
            builtins.open.__name__,
            return_value=MagicMock(
                __enter__=MagicMock(return_value=MagicMock(read=MagicMock(return_value='ABC\n')))
            ),
        ) as mock_open:
            agent_instance = Agent(self.config)

            mock_get_key_directory_path.assert_called_once_with(agent_instance.config)
            mock_mount_device.assert_called_once_with(agent_instance.config)
            mock_glob.assert_called_once_with('/mnt/test/uuid*.txt')
            mock_open.assert_called_once_with('/mnt/test/uuid_123.txt')
            mock_open.return_value.__enter__.assert_called_once_with()
            self.assertEqual(agent_instance.identity, 'abc')
            mock_open.return_value.__exit__.assert_called_once()

    @patch('subprocess.run')
    @patch('agent.parse_instructions')
    @patch('agent.fix_clock')
    def test_get_identity_failed_mount(self, *args):
        with patch.object(agent, agent.mount_device.__name__, return_value=False), patch.object(
            agent, agent.get_key_directory_path.__name__
        ):
            agent_instance = Agent(self.config)

            self.assertIsNone(agent_instance.identity)

    @patch('subprocess.run')
    @patch('agent.parse_instructions')
    @patch('agent.fix_clock')
    def test_get_identity_no_file(self, *args):
        with patch.object(agent, agent.mount_device.__name__, return_value=True), patch.object(
            agent.glob, agent.glob.glob.__name__, return_value=[]
        ), patch.object(agent, agent.get_key_directory_path.__name__):
            agent_instance = Agent(self.config)

            self.assertIsNone(agent_instance.identity)



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

    def test_get_key(self):
        with patch.object(
            agent,
            agent.get_key_directory_path.__name__,
            return_value=MagicMock(
                spec=Path,
                __truediv__=MagicMock(
                    return_value=MagicMock(
                        is_file=MagicMock(return_value=True),
                        open=MagicMock(
                            return_value=MagicMock(
                                __enter__=MagicMock(
                                    return_value=MagicMock(read=MagicMock(return_value='foo\n'))
                                )
                            )
                        ),
                    )
                ),
            ),
        ):
            self.assertEqual(self.agent.get_key('123-456'), 'foo')

    @patch('logging.error')
    def test_get_key_failed(self, mock_log):
        with patch.object(
            agent,
            agent.get_key_directory_path.__name__,
            return_value=MagicMock(
                spec=Path,
                __truediv__=MagicMock(return_value=MagicMock(is_file=MagicMock(return_value=False))),
            ),
        ):
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

    @patch('agent.sleep')
    @patch('builtins.open')
    def test_signal_watch_empty(self, mock_open, *args):
        mock_channel = MagicMock()
        mock_channel.readline.return_value = b''
        mock_open.return_value = mock_channel
        self.agent.signal_watch(test=True)
        mock_channel.close.assert_not_called()

    @patch('agent.parse_instructions', return_value=True)
    @patch('agent.sleep')
    @patch('subprocess.run')
    @patch('builtins.open')
    def test_signal_watch_resize(self, mock_open, mock_run, *args):
        rows = 10
        cols = 20
        mock_channel = MagicMock()
        mock_channel.readline.return_value = f'123456:resize_{rows}_{cols}\n'.encode('utf-8')
        mock_open.return_value = mock_channel
        self.agent.signal_watch(test=True)
        mock_for_assert = MagicMock()
        mock_for_assert(['stty', '-F', '/dev/ttyS0', 'rows', str(rows)], check=False)
        mock_for_assert(['stty', '-F', '/dev/ttyS0', 'cols', str(cols)], check=False)
        self.assertEqual(mock_run.mock_calls, mock_for_assert.mock_calls)

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
    def test_auto_update(
        self, mock_fix, mock_parse, mock_exec, mock_move, mock_ls, mock_cwd, mock_clone, mock_rm, mock_get
    ):
        mock_get.return_value.text = "AGENT_VERSION = '2.0.0'\n"
        testagent = Agent(self.config)
        testagent.config['AUTO_UPDATE'] = 'True'
        testagent.auto_update()
        mock_get.assert_called_with(self.config['VERSION_URL'])
        mock_rm.assert_called_with('/tmp/air-agent')
        mock_clone.assert_called_with(
            self.config['GIT_URL'], '/tmp/air-agent', branch=self.config['GIT_BRANCH']
        )
        mock_move.assert_called_with('/tmp/air-agent/test.py', '/tmp/foo/test.py')
        mock_exec.assert_called_with(sys.executable, ['python3'] + sys.argv)

    @patch('requests.get')
    @patch('agent.AGENT_VERSION', '1.4.3')
    @patch('git.Repo.clone_from')
    @patch('agent.parse_instructions')
    @patch('logging.debug')
    @patch('agent.fix_clock')
    def test_auto_update_latest(self, mock_fix, mock_log, mock_parse, mock_clone, mock_get):
        mock_get.return_value.text = "AGENT_VERSION = '1.4.3'\n"
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
    def test_auto_update_rm_safe(
        self, mock_fix, mock_parse, mock_exec, mock_move, mock_ls, mock_cwd, mock_clone, mock_rm, mock_get
    ):
        mock_get.return_value.text = "AGENT_VERSION = '2.0.0'\n"
        testagent = Agent(self.config)
        testagent.config['AUTO_UPDATE'] = 'True'
        testagent.auto_update()
        mock_get.assert_called_with(self.config['VERSION_URL'])
        mock_rm.assert_called_with('/tmp/air-agent')
        mock_clone.assert_called_with(
            self.config['GIT_URL'], '/tmp/air-agent', branch=self.config['GIT_BRANCH']
        )
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
    def test_auto_update_error(
        self,
        mock_fix,
        mock_log,
        mock_parse,
        mock_exec,
        mock_move,
        mock_ls,
        mock_cwd,
        mock_clone,
        mock_rm,
        mock_get,
    ):
        mock_get.return_value.text = "AGENT_VERSION = '2.0.0'\n"
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

    @patch('argparse.ArgumentParser')
    def test_parse_args(self, mock_argparse):
        default_config_file = '/mnt/air/agent.ini'
        mock_parser = MagicMock()
        mock_argparse.return_value = mock_parser
        mock_parser.add_argument = MagicMock()
        mock_parser.parse_args.return_value = 'foo'
        res = agent.parse_args()
        year = datetime.now().year
        mock_argparse.assert_called_with(description='Air Agent service ' + f'(NVIDIA © {year})')
        mock_parser.add_argument.assert_called_with(
            '-c',
            '--config-file',
            default=default_config_file,
            help="Location of the service's config file. "
            + 'Normally this will be injected automatically by the Air platform '
            + f'(default: {default_config_file})',
        )
        self.assertEqual(res, 'foo')

    @patch('agent.executors')
    @patch('agent.sleep')
    @patch(
        'agent.Agent.get_instructions', return_value=[{'data': 'foo', 'executor': 'shell', 'monitor': None}]
    )
    @patch('threading.Thread')
    @patch('agent.Agent.auto_update')
    @patch('agent.fix_clock')
    def test_start_daemon(self, mock_fix, mock_update, mock_threading, mock_parse, mock_sleep, mock_exec):
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
    def test_start_daemon_no_change(self, mock_fix, mock_threading, mock_parse, mock_sleep, mock_exec):
        Agent.get_identity = MagicMock(return_value='123-456')
        agent_obj = Agent(self.config)
        agent_obj.get_instructions = MagicMock()
        agent_obj.check_identity = MagicMock(return_value=True)
        agent.start_daemon(agent_obj, test=True)
        agent_obj.get_instructions.assert_not_called()
        mock_parse.assert_called()

    @patch('agent.executors')
    @patch('agent.sleep')
    @patch(
        'agent.Agent.get_instructions', return_value=[{'data': 'foo', 'executor': 'shell', 'monitor': None}]
    )
    @patch('threading.Thread')
    @patch('agent.fix_clock')
    def test_start_daemon_command_failed(self, mock_fix, mock_threading, mock_parse, mock_sleep, mock_exec):
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
            {'executor': 'shell', 'data': 'bar', 'monitor': None},
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
        mock_agent.get_instructions.return_value = [{'executor': 'test', 'data': 'foo', 'monitor': None}]
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
        retries = 10
        mock_agent = MagicMock()
        mock_agent.get_instructions.return_value = False
        res = agent.parse_instructions(mock_agent, attempt=1)
        self.assertEqual(len(mock_sleep.mock_calls), retries)
        self.assertEqual(mock_sleep.mock_calls[0], call(10))
        self.assertEqual(mock_sleep.mock_calls[retries - 1], call(retries * 10))
        self.assertEqual(mock_agent.get_instructions.call_count, retries + 1)
        self.assertFalse(res)
        mock_agent.lock.acquire.assert_called()
        mock_agent.unlock.assert_called()

    @patch('agent.executors')
    @patch('logging.warning')
    @patch('agent.sleep')
    def test_parse_instructions_cmd_failed(self, mock_sleep, mock_log, mock_exec):
        mock_exec.EXECUTOR_MAP = {'shell': MagicMock(side_effect=[False, False, True])}
        mock_agent = MagicMock()
        mock_agent.get_instructions.return_value = [{'executor': 'shell', 'data': 'foo', 'monitor': None}]
        mock_agent.get_identity = MagicMock(return_value='abc')
        agent.parse_instructions(mock_agent)
        assert_logs = MagicMock()
        assert_logs.warning(
            'Failed to execute all instructions on attempt #1. ' + 'Retrying in 10 seconds...'
        )
        assert_logs.warning(
            'Failed to execute all instructions on attempt #2. ' + 'Retrying in 20 seconds...'
        )
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
        mock_agent.get_instructions.return_value = [{'executor': 'shell', 'data': 'foo', 'monitor': None}]
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
        mock_agent.get_instructions.return_value = [
            {'executor': 'shell', 'data': 'foo', 'monitor': monitor_str}
        ]
        mock_channel = MagicMock()
        agent.parse_instructions(mock_agent, channel=mock_channel)
        mock_thread_class.assert_called_with(
            target=mock_agent.monitor, args=(mock_channel,), kwargs=json.loads(monitor_str)
        )
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

    @patch(
        'subprocess.check_output', return_value=b'ntp.service\nfoo.service\nntp@mgmt.service\nchrony.service'
    )
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

    def test_check_devices(self):
        with patch.object(
            agent,
            agent.get_key_device_path.__name__,
            return_value=MagicMock(spec=Path, exists=MagicMock(return_value=True)),
        ), patch.object(
            agent, agent.get_key_directory_path.__name__, return_value=Path('/mnt/test/')
        ), patch.object(subprocess, subprocess.run.__name__) as mock_subprocess_run, patch.object(
            agent, agent.mount_device.__name__, return_value=True
        ):
            res = agent.check_devices(self.config)
            self.assertTrue(res)
            mock_subprocess_run.assert_called_once_with('ls /mnt/test/uuid*', shell=True)

    def test_check_devices_path_does_not_exist(self):
        with patch.object(
            agent,
            agent.get_key_device_path.__name__,
            return_value=MagicMock(spec=Path, exists=MagicMock(return_value=False)),
        ):
            self.assertFalse(agent.check_devices(self.config))

    def test_check_devices_mount_failed(self):
        with patch.object(
            agent,
            agent.get_key_device_path.__name__,
            return_value=MagicMock(spec=Path, exists=MagicMock(return_value=True)),
        ), patch.object(
            agent, agent.get_key_directory_path.__name__, return_value=Path('/mnt/test/')
        ), patch.object(agent, agent.mount_device.__name__, return_value=False):
            self.assertFalse(agent.check_devices(self.config))

    def test_check_devices_ls_failed(self):
        with patch.object(
            agent,
            agent.get_key_device_path.__name__,
            return_value=MagicMock(spec=Path, exists=MagicMock(return_value=True)),
        ), patch.object(
            agent, agent.get_key_directory_path.__name__, return_value=Path('/mnt/test/')
        ), patch.object(subprocess, subprocess.run.__name__, side_effect=Exception), patch.object(
            agent, agent.mount_device.__name__, return_value=True
        ):
            self.assertFalse(agent.check_devices(self.config))

    @patch('subprocess.run')
    def test_mount_device(self, mock_run):
        with patch.object(
            agent, agent.get_key_device_path.__name__, return_value=Path('/dev/foo')
        ) as mock_get_key_device_path, patch.object(
            agent,
            agent.get_key_directory_path.__name__,
            return_value=MagicMock(
                spec=Path, exists=MagicMock(return_value=True), __str__=MagicMock(return_value='/mnt/bar/')
            ),
        ) as mock_get_key_directory_path:
            res = agent.mount_device(self.config)

            mock_get_key_device_path.assert_called_once_with(self.config)
            mock_get_key_directory_path.assert_called_once_with(self.config)
            mock_run.assert_called_with('mount /dev/foo /mnt/bar/ 2>/dev/null', shell=True)
            self.assertTrue(res)

    @patch('os.makedirs')
    @patch('subprocess.run')
    @patch('logging.debug')
    def test_mount_device_directory_does_not_exist(self, mock_log, mock_run, mock_dir):
        with patch.object(
            agent, agent.get_key_device_path.__name__, return_value=Path('/dev/foo')
        ), patch.object(
            agent,
            agent.get_key_directory_path.__name__,
            return_value=MagicMock(
                spec=Path, exists=MagicMock(return_value=False), __str__=MagicMock(return_value='/mnt/bar/')
            ),
        ):
            res = agent.mount_device(self.config)
            self.assertTrue(res)
            mock_log.assert_called_with('/mnt/bar/ does not exist, creating')
            mock_dir.assert_called_with('/mnt/bar/')
            mock_run.assert_called_with('mount /dev/foo /mnt/bar/ 2>/dev/null', shell=True)

    @patch('subprocess.run')
    def test_mount_device_directory_exists(self, mock_run):
        with patch.object(
            agent, agent.get_key_device_path.__name__, return_value=Path('/dev/foo')
        ), patch.object(
            agent,
            agent.get_key_directory_path.__name__,
            return_value=MagicMock(
                spec=Path, exists=MagicMock(return_value=True), __str__=MagicMock(return_value='/mnt/bar/')
            ),
        ):
            res = agent.mount_device(self.config)
            self.assertTrue(res)
            mock_run.assert_has_calls(
                [
                    call('umount /mnt/bar/ 2>/dev/null', shell=True),
                    call('mount /dev/foo /mnt/bar/ 2>/dev/null', shell=True),
                ]
            )

    @patch('os.makedirs', side_effect=Exception)
    @patch('logging.error')
    def test_mount_device_directory_create_failed(self, mock_log, mock_dir):
        with patch.object(agent, agent.get_key_device_path.__name__), patch.object(
            agent,
            agent.get_key_directory_path.__name__,
            return_value=MagicMock(
                spec=Path, exists=MagicMock(return_value=False), __str__=MagicMock(return_value='/mnt/bar/')
            ),
        ):
            res = agent.mount_device(self.config)
            self.assertFalse(res)
            mock_log.assert_called_with('Failed to create the /mnt/bar/ directory')

    @patch('subprocess.run')
    @patch('logging.debug')
    def test_mount_device_unmount_failed(self, mock_log, mock_run):
        with patch.object(agent, agent.get_key_device_path.__name__), patch.object(
            agent,
            agent.get_key_directory_path.__name__,
            return_value=MagicMock(
                spec=Path, exists=MagicMock(return_value=True), __str__=MagicMock(return_value='/mnt/bar/')
            ),
        ):
            cmd2 = MagicMock()
            mock_run.side_effect = [subprocess.CalledProcessError(1, 'a'), cmd2]
            res = agent.mount_device(self.config)
            self.assertTrue(res)
            mock_log.assert_called_with('/mnt/bar/ exists but is not mounted')

    @patch('subprocess.run')
    @patch('logging.error')
    def test_mount_device_mount_failed(self, mock_log, mock_run):
        with patch.object(
            agent, agent.get_key_device_path.__name__, return_value=Path('/dev/foo')
        ), patch.object(
            agent,
            agent.get_key_directory_path.__name__,
            return_value=MagicMock(
                spec=Path, exists=MagicMock(return_value=True), __str__=MagicMock(return_value='/mnt/bar/')
            ),
        ):
            cmd1 = MagicMock()
            mock_run.side_effect = [cmd1, subprocess.CalledProcessError(1, 'a')]
            res = agent.mount_device(self.config)
            self.assertFalse(res)
            mock_log.assert_called_with('Failed to mount /dev/foo to /mnt/bar/')

    def test_get_key_device_path(self):
        with patch.object(
            subprocess, subprocess.run.__name__, return_value=MagicMock(stdout='/dev/test2\n')
        ) as mock_subprocess:
            return_value = agent.get_key_device_path(self.config)

            mock_subprocess.assert_called_once_with(
                ('blkid', '--label', 'testid'), text=True, check=True, capture_output=True
            )
            self.assertEqual(return_value, Path('/dev/test2'))

    def test_get_key_device_path_default_volume_id(self):
        with patch.object(
            subprocess, subprocess.run.__name__, return_value=MagicMock(stdout='/dev/test2\n')
        ) as mock_subprocess:
            del self.config['KEY_DEVICE_VOLUME_ID']
            return_value = agent.get_key_device_path(self.config)

            mock_subprocess.assert_called_once_with(
                ('blkid', '--label', 'airagent'), text=True, check=True, capture_output=True
            )
            self.assertEqual(return_value, Path('/dev/test2'))

    def test_get_key_device_path_command_errors(self):
        for exception in (subprocess.CalledProcessError, Exception):
            with self.subTest(exception=exception), patch.object(
                subprocess, subprocess.run.__name__, return_value=exception
            ):
                return_value = agent.get_key_device_path(self.config)
                self.assertEqual(return_value, Path('/dev/test'))

    def test_get_key_device_path_fallback(self):
        with patch.object(subprocess, subprocess.run.__name__, return_value=Exception):
            del self.config['KEY_DEVICE']
            return_value = agent.get_key_device_path(self.config)
            self.assertEqual(return_value, Path('/dev/vdb'))

    def test_get_key_directory_path(self):
        self.assertEqual(agent.get_key_directory_path(self.config), Path('/mnt/test/'))

    def test_get_key_directory_path_override(self):
        del self.config['KEY_DIR']
        self.assertEqual(agent.get_key_directory_path(self.config), Path('/mnt/air/'))


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
        mock_log.assert_called_with(
            'Failed to decode instructions as JSON: ' + 'Expecting value: line 1 column 38 (char 37)'
        )

    @patch('executors.shell')
    def test_init(self, mock_shell):
        res = executors.init('{"hostname": "test"}')
        self.assertTrue(res)

    @patch('logging.error')
    def test_init_json_parse_failed(self, mock_log):
        res = executors.init('string')
        mock_log.assert_called_with(
            'Failed to decode init data as JSON: ' + 'Expecting value: line 1 column 1 (char 0)'
        )
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
