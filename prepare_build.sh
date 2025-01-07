#!/usr/bin/env bash

CURRENT_VERSION=`poetry version -s`
echo $CURRENT_VERSION
if [ "$VERSION" = "major" ]; then
  poetry version major
elif [ "$VERSION" = "minor" ]; then
  poetry version minor
elif [ "$VERSION" = "patch" ]; then
  poetry version patch
else
  echo Version must be either major, minor or patch
  exit 1
fi
