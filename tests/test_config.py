# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Unit tests for Config module
"""
#pylint: disable=unused-argument,missing-class-docstring,missing-function-docstring
#pylint: disable=arguments-differ,no-self-use,too-many-public-methods,too-many-arguments

import tempfile
from unittest import TestCase
from unittest.mock import patch

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

    def test_getitem(self):
        self.assertEqual(self.config[self.key], self.value)

    def test_getitem_env_override(self):
        value = 'foo'
        with patch('config.os.getenv', return_value=value) as mock_env:
            self.assertEqual(self.config[self.key], value)
        mock_env.assert_called_once_with(f'AIR_AGENT_{self.key}', self.value)
