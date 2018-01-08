#!/usr/bin/env bash
set -x -e

if [ -n "$TRAVIS_BUILD_DIR" ]; then
   # Build and install conan
   pip install conan/ -e conan/.[dev]
fi

echo -e "\n  ..... Running flake8 on conan to check style and docstrings"
flake8 conan/conan --ignore=E501

echo -e "\n  ..... Running flake8 on tests to check style and docstrings"
flake8 conan/tests --ignore=E501

echo -e "\n  ..... Running unit tests with pytest"
pushd conan
python setup.py test
popd

set +x
echo 'Success!'
