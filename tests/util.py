# SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Test utils
"""

import configparser

CONFIG_FILE = 'tests/agent.ini'


def load_config():
    """
    Helper function to load the test config file.

    Returns:
    dict - A dictionary of all loaded config values
    """
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    return config['AGENT']
