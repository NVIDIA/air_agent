#! /bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

coverage run --omit='tests/*,**/__init__.py,version.py' --source='./' `which pytest` tests/tests.py
coverage report -m
coverage html
