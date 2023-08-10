# SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
""" Config module """
import os

import configparser

class Config(configparser.SectionProxy):
    """ Wraps a ConfigParser dict-like to allow overriding the agent config via environment variables """
    def __init__(self, filename):
        parser = configparser.ConfigParser()
        parser.read(filename)
        super().__init__(parser, 'AGENT')

    def __getitem__(self, key):
        env_prefix = 'AIR_AGENT_'
        return os.getenv(env_prefix + key, super().__getitem__(key))
