#! /bin/bash

coverage run --omit='tests/*,**/__init__.py,version.py' --source='./' `which pytest` tests/tests.py
coverage report -m
coverage html
