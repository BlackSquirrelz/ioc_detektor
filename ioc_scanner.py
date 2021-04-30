#!/usr/bin/venv python3
# -*- coding: utf-8 -*-
# ioc_scanner.py

# Author: BlackSquirrelz
# Date: 2021-03-10
# Description: Tool to scan log files for Known IOCs

import logging
import argparse
from datetime import date as dtd
from datetime import datetime
import time
import scanner_logic as sl
import testing.efficiency_test as profiler


@profiler.profile
def process_file(args, file):

    current_date = dtd.today()
    print(current_date)

    if args.output is not None:
        outfile = args.output
    else:
        outfile = "output/" + str(current_date) + "_scan_results.txt"

    # Setting Defaults file locations
    default_ip_file = "iocs/ioc_ip.txt"
    default_regex_file = "iocs/ioc_regex.txt"
    default_shells_file = "iocs/ioc_shells.txt"
    default_hashes_file = "iocs/ioc_hashes.txt"

    if args.all is True:
        sl.get_ip(file)
        sl.generic_regex(default_regex_file, file)

    if args.ipaddress is True:
        sl.get_ip(file, default_ip_file)

    if args.regex is True:
        sl.generic_regex(default_regex_file, file)

    if args.shells is True:
        print("Getting Regex")

    if args.hashes is True:
        sl.scan_hashes(file, default_hashes_file)


def timestats(start_time, end_time):
    elapsed_time = end_time - start_time
    print(f"\nStarted at: {start_time}")
    print(f"Stopped at: {end_time}")
    print(f"Elapsed Time {elapsed_time}")


def write_results():
    pass


if __name__ == '__main__':
    """Takes arguments, -a ALL -o OUTPUT -d ROOT_DIRECTORY -f FILE -ip IP -re REGEX -s SHELLS -h HASHES -? HELP."""

    parser = argparse.ArgumentParser()

    # -a ALL -o OUTPUT -d ROOT_DIRECTORY -f FILE -ip IP -re REGEX -s SHELLS -h HASHES -? HELP
    parser.add_argument("-a", "--all", help="Run all tests, can take significant time.", action='store_true')
    parser.add_argument("-c", "--case", help="Optional Case Name")
    parser.add_argument("-o", "--output", help="Specify output file name", action='store_true')
    parser.add_argument("-d", "--directory", help="Specify directory to start search")
    parser.add_argument("-f", "--file", help="Specify single file for search")
    parser.add_argument("-ip", "--ipaddress", help="Check for IP Addresses", action='store_true')
    parser.add_argument("-re", "--regex", help="Check for Regex", action='store_true')
    parser.add_argument("-s", "--shells", help="Check presence of Shells", action='store_true')
    parser.add_argument("-ha", "--hashes", help="Check for presence of Hashes", action='store_true')

    args = parser.parse_args()

    # Get Runtime stats
    start_time = datetime.now()

    print(25 * '-+-' + ' Start of Processing ' + 25 * '-+-')
    print(start_time)
    case_number = args.case
    print(args.ipaddress)

    if args.directory is not None:
        dir_path = args.directory

        for file in dir_path:
            process_file(args, file)
            print(file)

        logging.info(f'Setting root to: {args.directory}')
    elif args.file is not None:
        process_file(args, args.file)
        logging.info(f'Starting single file scan on {args.file}')
    else:
        print(f"No vaild input was supplied, exiting program, use -h / -? for help.")
        exit(1)

    # End Time and elapsed time.
    end_time = datetime.now()
    print(25 * '-*-' + ' End of Processing ' + 25 * '-*-')
    timestats(start_time, end_time)
