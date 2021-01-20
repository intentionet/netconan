"""A setuptools based setup module.

See:
https://packaging.python.org/en/latest/distributing.html
https://github.com/pypa/sampleproject
"""
#   Copyright 2018 Intentionet
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

from os import path

# Always prefer setuptools over distutils
from setuptools import find_packages, setup

here = path.abspath(path.dirname(__file__))

about = {}
with open(path.join(here, "netconan", "__init__.py"), "r") as f:
    exec(f.read(), about)

with open(path.join(here, "README.rst")) as f:
    readme = f.read()

setup(
    name=about["__name__"],
    # Versions should comply with PEP440.  For a discussion on single-sourcing
    # the version across setup.py and the project code, see
    # https://packaging.python.org/en/latest/single_source_version.html
    version=about["__version__"],
    description=about["__desc__"],
    long_description=readme,
    # The project's main homepage.
    url=about["__url__"],
    # Author details
    author="Intentionet",
    author_email="netconan-dev@intentionet.com",
    # Choose your license
    license="Apache License 2.0",
    # What does your project relate to?
    keywords="network configuration anonymizer",
    # You can just specify the packages manually here if your project is
    # simple. Or you can use find_packages().
    packages=find_packages(exclude=["contrib", "docs", "tests"]),
    # Alternatively, if you want to distribute just a my_module.py, uncomment
    # this:
    #   py_modules=["my_module"],
    # List run-time dependencies here.  These will be installed by pip when
    # your project is installed. For an analysis of "install_requires" vs pip's
    # requirements files see:
    # https://packaging.python.org/en/latest/requirements.html
    install_requires=[
        "configargparse<1.0.0",
        "bidict<1.0.0",
        # Only use enum34 for Python older than 3.4
        'enum34<2.0.0; python_version < "3.4"',
        "ipaddress<2.0.0",
        "passlib<2.0.0",
        "six<2.0.0",
    ],
    # List additional groups of dependencies here (e.g. development
    # dependencies). You can install these using the following syntax,
    # for example:
    # $ pip install -e .[dev,test]
    extras_require={
        "dev": ["flake8<4.0.0", "flake8-docstrings<2.0.0", "pydocstyle<4.0.0"],
        # Duplicated test deps here for now, since dependency resolution is
        # failing for python2.7 in CI
        "test": [
            "pytest>=4.6.0,<5.0.0",
            "pytest-cov<3.0.0",
            "requests_mock<2.0.0",
            "testfixtures<7.0.0",
            # zipp 2.2 does not work w/ Python < 3.6
            "zipp<2.2",
        ],
    },
    # List pytest requirements for running unit tests
    setup_requires=["pytest-runner<6.0"],
    # pytest 5+ does not support Python 2
    tests_require=[
        "pytest>=4.6.0,<5.0.0",
        "pytest-cov<3.0.0",
        "requests_mock<2.0.0",
        "testfixtures<7.0.0",
        # zipp 2.2 does not work w/ Python < 3.6
        "zipp<2.2",
    ],
    # If there are data files included in your packages that need to be
    # installed, specify them here.  If using Python 2.6 or less, then these
    # have to be included in MANIFEST.in as well.
    package_data={},
    # Although 'package_data' is the preferred approach, in some case you may
    # need to place data files outside of your packages. See:
    # http://docs.python.org/3.4/distutils/setupscript.html#installing-additional-files # noqa
    # In this case, 'data_file' will be installed into '<sys.prefix>/my_data'
    data_files=[],
    # To provide executable scripts, use entry points in preference to the
    # "scripts" keyword. Entry points provide cross-platform support and allow
    # pip to create the appropriate form of executable for the target platform.
    entry_points={
        "console_scripts": [
            "netconan = netconan.netconan:main",
        ],
    },
)
