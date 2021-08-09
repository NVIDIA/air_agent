#! /bin/bash

coverage run --omit='tests.py' --source='./' `which pytest` *.py
coverage report -m
coverage html
