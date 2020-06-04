"""
Unit tests for Agent module
"""
#pylint: disable=unused-argument,missing-class-docstring,missing-function-docstring
#pylint: disable=arguments-differ,no-self-use,too-many-public-methods

import subprocess
from datetime import datetime
from unittest import TestCase
from unittest.mock import MagicMock, patch

from cryptography.fernet import Fernet

import agent
import executors
from agent import Agent

MOCK_INI = {'AGENT': {'CHECK_INTERVAL': 60, 'AIR_API': 'http://localhost:8000', 'KEY_DIR': './',
                      'LOG_LEVEL': 'DEBUG'}}
MOCK_CONFIG = MOCK_INI['AGENT']

class TestAgentIdentity(TestCase):
    @patch('subprocess.run')
    @patch('glob.glob', return_value=['./uuid_123.txt'])
    @patch('builtins.open')
    @patch('agent.parse_instructions')
    def test_get_identity(self, mock_parse, mock_open, mock_glob, mock_run):
        mock_file = MagicMock()
        mock_file.read = MagicMock(return_value='ABC\n')
        mock_open.return_value.__enter__.return_value = mock_file
        agent_obj = Agent(MOCK_CONFIG)
        res = agent_obj.get_identity()
        key_dir = MOCK_CONFIG['KEY_DIR']
        mock_open.assert_called_with(f'{key_dir}uuid_123.txt')
        self.assertEqual(res, 'abc')

    @patch('subprocess.run', side_effect=[subprocess.CalledProcessError(1, 'a'), True, True, True])
    @patch('logging.debug')
    @patch('agent.parse_instructions')
    def test_get_identity_failed_umount(self, mock_parse, mock_log, mock_run):
        agent_obj = Agent(MOCK_CONFIG)
        res = agent_obj.get_identity()
        self.assertIsNone(res)
        key_dir = MOCK_CONFIG['KEY_DIR']
        mock_log.assert_called_with(f'{key_dir} is not mounted')

    @patch('subprocess.run', side_effect=[True, True, True, subprocess.CalledProcessError(1, 'a')])
    @patch('logging.error')
    @patch('agent.parse_instructions')
    def test_get_identity_failed_mount(self, mock_parse, mock_log, mock_run):
        agent_obj = Agent(MOCK_CONFIG)
        res = agent_obj.get_identity()
        self.assertIsNone(res)
        key_dir = MOCK_CONFIG['KEY_DIR']
        mock_log.assert_called_with(f'Failed to refresh {key_dir}')

    @patch('subprocess.run')
    @patch('glob.glob', return_value=[])
    @patch('logging.error')
    @patch('agent.parse_instructions')
    def test_get_identity_no_file(self, mock_parse, mock_log, mock_glob, mock_run):
        agent_obj = Agent(MOCK_CONFIG)
        res = agent_obj.get_identity()
        self.assertIsNone(res)
        mock_log.assert_called_with('Failed to find identity file')

class TestAgent(TestCase):
    @patch('agent.parse_instructions')
    def setUp(self, mock_parse):
        self.mock_id = MagicMock(return_value='123-456')
        Agent.get_identity = self.mock_id
        self.agent = Agent(MOCK_CONFIG)

    def test_init(self):
        self.assertDictEqual(self.agent.config, MOCK_CONFIG)
        self.mock_id.assert_called()
        self.assertEqual(self.agent.identity, '123-456')

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
        self.assertDictEqual(res, instructions)

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
        url = MOCK_CONFIG['AIR_API'] + f'simulation-node/{self.agent.identity}/instructions/'
        self.agent.delete_instructions()
        mock_delete.assert_called_with(url)

    @patch('requests.delete', side_effect=Exception)
    @patch('logging.error')
    def test_delete_instructions_failed(self, mock_log, mock_delete):
        self.agent.delete_instructions()
        mock_log.assert_called_with('Failed to delete post-clone instructions')

class TestAgentFunctions(TestCase):
    class MockConfigParser(dict):
        def __init__(self):
            super().__init__()
            self.read = MagicMock()

    def setUp(self):
        self.mock_parse = self.MockConfigParser()

    @patch('configparser.ConfigParser')
    def test_load_config(self, mock_confparse):
        mock_confparse.return_value = self.mock_parse
        self.mock_parse['AGENT'] = MOCK_CONFIG
        res = agent.load_config('test.txt')
        self.assertDictEqual(res, MOCK_CONFIG)
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
        mock_argparse.assert_called_with(description='AIR Agent service ' + \
                                         f'(Cumulus Networks © {year})')
        mock_parser.add_argument.assert_called_with('-c', '--config-file',
                                                    help='Location of the service\'s config ' + \
                                                    'file (default: /etc/cumulus-air/agent.ini)',
                                                    default='/etc/cumulus-air/agent.ini')
        self.assertEqual(res, 'foo')

    @patch('agent.executors')
    @patch('agent.sleep')
    @patch('agent.Agent.get_instructions', return_value=[{'data': 'foo', 'executor': 'shell'}])
    def test_start_daemon(self, mock_parse, mock_sleep, mock_exec):
        mock_exec.EXECUTOR_MAP = {'shell': MagicMock()}
        Agent.get_identity = MagicMock(return_value='123-456')
        agent_obj = Agent(MOCK_CONFIG)
        agent_obj.check_identity = MagicMock(return_value=False)
        agent_obj.delete_instructions = MagicMock()
        agent.clock_jumped = MagicMock(return_value=True)
        agent.fix_clock = MagicMock()
        agent.start_daemon(agent_obj, test=True)
        mock_exec.EXECUTOR_MAP['shell'].assert_called_with('foo')
        agent_obj.delete_instructions.assert_called()
        mock_sleep.assert_called_with(MOCK_CONFIG['CHECK_INTERVAL'])
        agent.fix_clock.assert_called()

    @patch('agent.executors')
    @patch('agent.sleep')
    @patch('agent.parse_instructions')
    def test_start_daemon_no_change(self, mock_parse, mock_sleep, mock_exec):
        Agent.get_identity = MagicMock(return_value='123-456')
        agent_obj = Agent(MOCK_CONFIG)
        agent_obj.get_instructions = MagicMock()
        agent_obj.check_identity = MagicMock(return_value=True)
        agent.start_daemon(agent_obj, test=True)
        agent_obj.get_instructions.assert_not_called()

    @patch('agent.executors')
    @patch('agent.sleep')
    @patch('agent.parse_instructions')
    def test_start_daemon_no_jump(self, mock_parse, mock_sleep, mock_exec):
        mock_exec.EXECUTOR_MAP = {'shell': MagicMock()}
        Agent.get_identity = MagicMock(return_value='123-456')
        agent_obj = Agent(MOCK_CONFIG)
        agent_obj.check_identity = MagicMock(return_value=False)
        agent_obj.delete_instructions = MagicMock()
        agent_obj.get_instructions = MagicMock(return_value=[{'data': 'foo', 'executor': 'shell'}])
        agent_obj.clock_jumped = MagicMock(return_value=False)
        agent_obj.fix_clock = MagicMock()
        agent.start_daemon(agent_obj, test=True)
        agent_obj.fix_clock.assert_not_called()

    @patch('agent.executors')
    @patch('agent.sleep')
    @patch('agent.Agent.get_instructions', return_value=[{'data': 'foo', 'executor': 'shell'}])
    def test_start_daemon_command_failed(self, mock_parse, mock_sleep, mock_exec):
        mock_exec.EXECUTOR_MAP = {'shell': MagicMock(return_value=False)}
        Agent.get_identity = MagicMock(return_value='123-456')
        agent_obj = Agent(MOCK_CONFIG)
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
            {'executor': 'shell', 'data': 'foo'},
            {'executor': 'shell', 'data': 'bar'}
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

    @patch('agent.executors')
    @patch('logging.warning')
    def test_parse_instructions_unsupported(self, mock_log, mock_exec):
        mock_exec.EXECUTOR_MAP = {'shell': MagicMock(side_effect=[1, 2])}
        mock_agent = MagicMock()
        mock_agent.get_instructions.return_value = [{'executor': 'test', 'data': 'foo'}]
        agent.parse_instructions(mock_agent)
        mock_log.assert_called_with('Received unsupported executor test')

    @patch('agent.sleep')
    def test_parse_instructions_failed(self, mock_sleep):
        mock_agent = MagicMock()
        mock_agent.get_instructions.side_effect = [False, []]
        agent.parse_instructions(mock_agent)
        mock_sleep.assert_called_with(30)
        self.assertEqual(mock_agent.get_instructions.call_count, 2)

    @patch('agent.executors')
    @patch('logging.warning')
    @patch('agent.sleep')
    def test_parse_instructions_cmd_failed(self, mock_sleep, mock_log, mock_exec):
        mock_exec.EXECUTOR_MAP = {'shell': MagicMock(side_effect=[False, False, True])}
        mock_agent = MagicMock()
        mock_agent.get_instructions.return_value = [{'executor': 'shell', 'data': 'foo'}]
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

    @patch('agent.executors')
    @patch('logging.error')
    @patch('agent.sleep')
    def test_parse_instructions_all_cmd_failed(self, mock_sleep, mock_log, mock_exec):
        mock_exec.EXECUTOR_MAP = {'shell': MagicMock(return_value=False)}
        mock_agent = MagicMock()
        mock_agent.get_instructions.return_value = [{'executor': 'shell', 'data': 'foo'}]
        mock_agent.get_identity = MagicMock(return_value='abc')
        agent.parse_instructions(mock_agent)
        assert_sleep = MagicMock()
        assert_sleep(10)
        assert_sleep(20)
        assert_sleep(30)
        self.assertEqual(mock_sleep.mock_calls, assert_sleep.mock_calls)
        mock_agent.get_identity.assert_not_called()
        mock_log.assert_called_with('Failed to execute all instructions. Giving up.')

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

    @patch('subprocess.check_output', return_value=b' 10000 seconds since 1969')
    @patch('agent.datetime')
    def test_clock_jumped_past(self, mock_datetime, mock_sub):
        mock_datetime.now = MagicMock(return_value=datetime(2020, 2, 1))
        mock_datetime.fromtimestamp = datetime.fromtimestamp
        res = agent.clock_jumped()
        self.assertTrue(res)

    @patch('subprocess.check_output', return_value=b' 99999999999999 seconds since 1969')
    @patch('agent.datetime')
    def test_clock_jumped_future(self, mock_datetime, mock_sub):
        mock_datetime.now = MagicMock(return_value=datetime(2020, 4, 1))
        mock_datetime.fromtimestamp = datetime.fromtimestamp
        res = agent.clock_jumped()
        self.assertTrue(res)

    @patch('subprocess.check_output', return_value=b' 1583038800 seconds since 1969')
    @patch('agent.datetime')
    def test_clock_jumped_no_jump(self, mock_datetime, mock_sub):
        mock_datetime.now = MagicMock(return_value=datetime.fromtimestamp(1583038800))
        mock_datetime.fromtimestamp = datetime.fromtimestamp
        res = agent.clock_jumped()
        self.assertFalse(res)

    @patch('subprocess.check_output', side_effect=Exception)
    @patch('agent.datetime')
    @patch('logging.warning')
    def test_clock_jumped_exception(self, mock_log, mock_datetime, mock_sub):
        mock_datetime.now = MagicMock(return_value=datetime(2020, 3, 1))
        mock_datetime.fromtimestamp = datetime.fromtimestamp
        res = agent.clock_jumped()
        self.assertTrue(res)
        mock_log.assert_called_with('Something went wrong. Syncing clock to be safe...')

    @patch('subprocess.check_output', return_value=b'foo')
    @patch('builtins.Exception')
    def test_clock_jumped_raised(self, mock_exception, mock_sub):
        agent.clock_jumped()
        mock_exception.assert_called_with('Unable to parse hardware clock')

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
