#! /bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2022-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

python3 -m coverage run --omit='tests/*,**/__init__.py,version.py' --source='./' -m pytest tests/tests.py
coverage report -m
coverage html
