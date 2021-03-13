#!/usr/bin/venv python3
# -*- coding: utf-8 -*-
# ioc_scanner.py

# Author: BlackSquirrelz
# Date: 2021-03-10
# Description: Script to get IP Addresses from Files, and compares them to known IOCs.

# Imports
import re
import file_handler
import logging


def get_ip(file):
    """Read Text from file and regex search for IP Addreses."""
    print(f"Extracting IP Addresses from {file}")
    # Setting Regexd Pattern for IP Extraction.
    pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    index = 0
    with open(file, 'r') as f:
        ip_dict = {
            file: []
        }
        for line in f:
            line = line.strip()
            index += 1

            hit = pattern.search(line)
            if hit is not None:
                logging.info(f"Line {index} in {file} contains IP: {hit[0]}.")
                ip_dict[file].append(hit[0])
    return ip_dict


def check_ip(suspect, confirmed):
    """Checking the found IP addresses against a list of IOC IP Addresses."""
    file_handler.read_file('iocs/ioc_ip.txt')
    if suspect in confirmed:
        logging.warning(f"Identified potential match {suspect}")


def generic_regex(regex_list, file):
    print(f"Searching for regex matches in {file}")

    with open(file, 'r') as f:
        # Setting Regexd Pattern for matching.
        hit_dict = {
            file: []
        }
        index = 0
        for line in f:
            index += 1
            for regex in regex_list:
                pattern = re.compile(regex)
                hit = pattern.search(line)
                if hit is not None:
                    logging.info(f"Line {index} in {file} contains pattern: {hit[0]}.")
                    hit_dict[file].append({'regex': regex, 'match': hit[0], 'line_number': index})
    print(hit_dict)
    return hit_dict

# TODO: Implement shell scanner
def scan_shells(file):
    print("Scanning for shells")

# TODO: Implement hash scanner
def scan_hashes(file):
    print("scanning for Hashes")


    """
    # PART ONE: Get all IP Addresses from the log files.
    ip_list = []
    regex_list = []

    regex_list = file_handler.read_file('iocs/ioc_regex.txt')

    for file in file_list:
        text = file_handler.read_file(file_path=file)
        ip_list.append(get_ip(file))
        regex_list.append(generic_regex(regex_list, file))

    outfile = 'output\\' + str(case_number) + '_Identified_IPS.txt' # Setting Variable to write an outfile.
    file_handler.save_json(outfile, ip_list)

    # PART TWO: Compare IP Addresses found to Known BAD IP Addresses
    known_bads = file_handler.read_file('iocs/ioc_ip.txt')
    known_bads = [ip.strip() for ip in known_bads]
    identified_ips = file_handler.get_json('output\\Identified_IPS.txt')
    bad_ips = []
    for entry in identified_ips:
        for item in entry:
            if item['IP'] in known_bads:
                #print(f'\tWarning {item["IP"]} in {item["file_path"]}, line #: {item["line_number"]} matches known IOC IP!')
                logging.warning(f'{item["IP"]} in {item["file_path"]}, line #: {item["line_number"]} matches known IOC IP!')
                bad_ips.append({'ip': item["IP"], 'path': item["file_path"]})

    # Writing Found BAD IP's
    bad_ip_outfile = 'output\\' + str(case_number) + "_IP_Matches"
    file_handler.save_json(bad_ip_outfile, bad_ips)

    # PART THREE: REGEX Matcher
    bad_regex = []
    for entry in regex_list:
        for item in entry:
            logging.warning(f'{item["Match"]} matches pattern {item["Regex"]} in file {item["file_path"]}, line #: {item["line_number"]}!')
            bad_regex.append({'match': item["Match"], 'path': item["file_path"]})

    bad_regex_outfile = 'output\\' + str(case_number) + "_REGEX_Matches"
    file_handler.save_json(bad_regex_outfile, bad_regex)

    print(25 * '-*-' + ' End of Processing ' + 25 * '-*-')
    """
