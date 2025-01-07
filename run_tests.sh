#! /bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

python3 -m coverage run -m pytest
coverage report -m
coverage html
