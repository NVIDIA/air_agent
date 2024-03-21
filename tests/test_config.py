# SPDX-FileCopyrightText: Copyright (c) 2023-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Unit tests for Config module
"""
# pylint: disable=unused-argument,missing-class-docstring,missing-function-docstring,protected-access
# pylint: disable=arguments-differ,no-self-use,too-many-public-methods,too-many-arguments

import tempfile
from unittest import TestCase
from unittest.mock import MagicMock, patch

import config


class TestConfig(TestCase):
    def setUp(self):
        self.key = 'TEST_KEY'
        self.value = 'testing'
        with tempfile.NamedTemporaryFile() as cfg_file:
            cfg_file.write(b'[AGENT]\n')
            cfg_file.write(f'{self.key}={self.value}\n'.encode('utf-8'))
            cfg_file.seek(0)
            self.config = config.Config(cfg_file.name)
        self.log_format = '%(asctime)s %(levelname)s %(message)s'

    def test_getitem(self):
        self.assertEqual(self.config[self.key], self.value)

    def test_getitem_env_override(self):
        value = 'foo'
        with patch('config.os.getenv', return_value=value) as mock_env:
            self.assertEqual(self.config[self.key], value)
        mock_env.assert_called_once_with(f'AIR_AGENT_{self.key}', self.value)

    @patch('config.logging')
    def test_init_logger(self, mock_logging):
        level = 'CRITICAL'
        log_file = '/tmp/agent.log'
        self.config['LOG_LEVEL'] = level
        self.config['LOG_FILE'] = log_file
        mock_handler = MagicMock()
        mock_logging.root.handlers = [mock_handler]

        self.config._init_logger()
        mock_logging.root.removeHandler(mock_handler)
        mock_logging.basicConfig.assert_called_once_with(
            filename=log_file, level=level, format=self.log_format
        )

    @patch('config.logging')
    def test_init_logger_default(self, mock_logging):
        self.config._init_logger()
        mock_logging.basicConfig.assert_called_once_with(
            filename='/var/log/air-agent.log', level='INFO', format=self.log_format
        )
