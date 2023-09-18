# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
""" Config module """
import configparser
import logging
import os

class Config(configparser.SectionProxy): #pylint: disable=too-many-ancestors
    """ Wraps a ConfigParser dict-like to allow overriding the agent config via environment variables """
    def __init__(self, filename):
        parser = configparser.ConfigParser()
        parser.read(filename)
        super().__init__(parser, 'AGENT')
        self._init_logger()

    def __getitem__(self, key):
        env_prefix = 'AIR_AGENT_'
        return os.getenv(env_prefix + key, super().__getitem__(key))

    def _init_logger(self):
        if self.get('LOG_LEVEL', '').upper() in ('CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG'):
            log_level = self['LOG_LEVEL'].upper()
        else:
            log_level = 'INFO'
        log_file = self.get('LOG_FILE', '/var/log/air-agent.log')

        for handler in logging.root.handlers:
            # Remove any existing handlers that may have been setup in case we're increasing verbosity
            # Once we require python >= 3.8 we can just use force=True on logging.basicConfig
            logging.root.removeHandler(handler)
        logging.basicConfig(filename=log_file, level=log_level,
                            format='%(asctime)s %(levelname)s %(message)s')
