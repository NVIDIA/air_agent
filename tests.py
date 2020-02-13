"""
Unit tests for Agent module
"""
#pylint: disable=unused-argument,missing-class-docstring,missing-function-docstring,arguments-differ

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
    def test_get_identity(self, mock_open, mock_glob, mock_run):
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
    def test_get_identity_failed_umount(self, mock_log, mock_run):
        agent_obj = Agent(MOCK_CONFIG)
        res = agent_obj.get_identity()
        self.assertIsNone(res)
        key_dir = MOCK_CONFIG['KEY_DIR']
        mock_log.assert_called_with(f'{key_dir} is not mounted')

    @patch('subprocess.run', side_effect=[True, True, True, subprocess.CalledProcessError(1, 'a')])
    @patch('logging.error')
    def test_get_identity_failed_mount(self, mock_log, mock_run):
        agent_obj = Agent(MOCK_CONFIG)
        res = agent_obj.get_identity()
        self.assertIsNone(res)
        key_dir = MOCK_CONFIG['KEY_DIR']
        mock_log.assert_called_with(f'Failed to refresh {key_dir}')

    @patch('subprocess.run')
    @patch('glob.glob', return_value=[])
    @patch('logging.error')
    def test_get_identity_no_file(self, mock_log, mock_glob, mock_run):
        agent_obj = Agent(MOCK_CONFIG)
        res = agent_obj.get_identity()
        self.assertIsNone(res)
        mock_log.assert_called_with('Failed to find identity file')

class TestAgent(TestCase):
    def setUp(self):
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
        self.assertDictEqual(res, {})
        mock_log.assert_called_with('Failed to get post-clone instructions')

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
    def test_start_daemon(self, mock_sleep, mock_exec):
        mock_exec.EXECUTOR_MAP = {'shell': MagicMock()}
        Agent.get_identity = MagicMock(return_value='123-456')
        agent_obj = Agent(MOCK_CONFIG)
        agent_obj.check_identity = MagicMock(return_value=False)
        agent_obj.delete_instructions = MagicMock()
        agent_obj.get_instructions = MagicMock(return_value=[{'data': 'foo', 'executor': 'shell'}])
        agent.start_daemon(agent_obj, test=True)
        mock_exec.EXECUTOR_MAP['shell'].assert_called_with('foo')
        agent_obj.delete_instructions.assert_called()
        mock_sleep.assert_called_with(MOCK_CONFIG['CHECK_INTERVAL'])

    @patch('agent.executors')
    @patch('agent.sleep')
    def test_start_daemon_no_change(self, mock_sleep, mock_exec):
        Agent.get_identity = MagicMock(return_value='123-456')
        agent_obj = Agent(MOCK_CONFIG)
        agent_obj.get_instructions = MagicMock()
        agent_obj.check_identity = MagicMock(return_value=True)
        agent.start_daemon(agent_obj, test=True)
        agent_obj.get_instructions.assert_not_called()

    @patch('agent.executors')
    @patch('agent.sleep')
    def test_start_daemon_command_failed(self, mock_sleep, mock_exec):
        mock_exec.EXECUTOR_MAP = {'shell': MagicMock(return_value=False)}
        Agent.get_identity = MagicMock(return_value='123-456')
        agent_obj = Agent(MOCK_CONFIG)
        agent_obj.check_identity = MagicMock(return_value=False)
        agent_obj.delete_instructions = MagicMock()
        agent_obj.get_instructions = MagicMock(return_value=[{'data': 'foo', 'executor': 'shell'}])
        agent.start_daemon(agent_obj, test=True)
        mock_exec.EXECUTOR_MAP['shell'].assert_called_with('foo')
        agent_obj.delete_instructions.assert_not_called()

    @patch('agent.executors')
    @patch('agent.sleep')
    @patch('logging.warning')
    def test_start_daemon_unsupported(self, mock_log, mock_sleep, mock_exec):
        mock_exec.EXECUTOR_MAP = {'shell': MagicMock()}
        Agent.get_identity = MagicMock(return_value='123-456')
        agent_obj = Agent(MOCK_CONFIG)
        agent_obj.check_identity = MagicMock(return_value=False)
        agent_obj.delete_instructions = MagicMock()
        agent_obj.get_instructions = MagicMock(return_value=[{'data': 'foo', 'executor': 'bar'}])
        agent.start_daemon(agent_obj, test=True)
        mock_log.assert_called_with('Received unsupported executor bar')

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
