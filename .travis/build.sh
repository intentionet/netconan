#!/usr/bin/env bash
set -x -e

if [ -n "$TRAVIS_BUILD_DIR" ]; then
   # Upgrade pip
   pip install -U pip
   # Build and install netconan
   pip install -e .[dev,test]
fi

echo -e "\n  ..... Running flake8 on netconan to check style and docstrings"
# Configuration for flake8 is taken from setup.cfg
flake8

echo -e "\n  ..... Running tests with pytest"
python setup.py test

set +x
echo 'Success!'
