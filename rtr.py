#!/usr/bin/env python

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import logging
import os
import subprocess
import sys

def cppcheck():
    command = 'cppcheck'
    args=os.environ["CPPCHECKARGS"]
    logging.debug(f'Executing {command} {args}')
    result = subprocess.run(f'{command} {args}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if result.returncode == 0 and not result.stderr:
        logging.info('CPPCHECK: succesfull')
        logging.info(result.stdout)
    else:
        logging.info('CPPCHECK: fail')
        logging.info(result.stderr)

    return bool(not result.returncode)

def clangformat():
    args = os.getenv("FORMATARGS")
    return True

def unittests():
    command = 'ctest'
    args = f'--test-dir {os.getenv("CMAKE_BUILDDIR")}'
    logging.debug(f'Executing {command} {args}')
    result = subprocess.run(f'{command} {args}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if result.returncode == 0 and not result.stderr:
        logging.info('TESTING: succesfull')
        logging.info(result.stdout)
    else:
        logging.info('TESTING: fail')
        logging.info(result.stderr)

    return bool(not result.returncode)

def configure():
    logging.info('Configuring')
    args = f'-B {os.getenv("CMAKE_BUILDDIR")} -DCMAKE_BUILD_TYPE={os.getenv("CMAKE_BUILD_TYPE")}'
    command = 'cmake'
    logging.debug(f'Executing {command} {args}')
    result = subprocess.run(f'{command} {args}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    return bool(not result.returncode)

def build():
    if configure():
        logging.info('Building')
        command = 'cmake'
        args = f'--build {os.getenv("CMAKE_BUILDDIR")} --config {os.getenv("CMAKE_BUILD_TYPE")}'
        logging.debug(f'Executing {command} {args}')
        result = subprocess.run(f'{command} {args}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        if result.returncode == 0 and not result.stderr:
            logging.info('BUILDING: succesfull')
            logging.info(result.stdout)
        else:
            logging.info('BUILDING: fail')
            logging.info(result.stderr)

        return bool(not result.returncode)

TESTS = {
    "cppcheck": cppcheck,
    "format": clangformat,
    "build": build,
    "tests" : unittests
}

def init_argparse():
    """Setup argparse for handle command line parameters.

    Returns:
        object: argparse parser object
    """
    parser = argparse.ArgumentParser(
        description="Tool to execute code quality validations."
    )
    parser.add_argument(
        "-V", help='Version and license message',
        action="store_true",
        dest='version'
    )
    parser.add_argument(
        "-t","--test", help='Test to execute. If omitted, all tests will be executed',
        action="append",
        dest='tests',
        choices=list(TESTS.keys())
    )
    parser.add_argument(
        "-q", help='Quiet execution',
        dest='quiet',
        action="store_true"
    )
    parser.add_argument(
        '-v', help='Verbose',
        dest='verbose',
        action='store_true'
    )
    return parser


def main():
    """RTR tool main function
    """
    # Parse cmdline args
    results = True
    parser = init_argparse()
    args = parser.parse_args()
    init_logger(args)

    if args.tests is None:
        args.tests = TESTS.keys()

    for test in args.tests:
        results = TESTS[test]() and results

    sys.exit(not int(results))

def init_logger(args):
    """[summary]

    Args:
        args ([type]): [description]
    """
    # Default logger configs
    logger_level = 'INFO'
    logger_fmt = '%(message)s'

    # Debug level if requested
    if args.verbose:
        logger_level = 'DEBUG'
        logger_fmt = '%(asctime)-15s %(module)s[%(levelname)s] %(message)s'

    # Handle quiet request
    if args.quiet:
        logger_level = 'ERROR'
        logger_fmt = ''

    # Set logging configs
    logging.basicConfig(format=logger_fmt, level=logger_level)

if __name__ == "__main__":
    main()
