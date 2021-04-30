#!/usr/bin/venv python3
# -*- coding: utf-8 -*-
# ioc_scanner.py

# Author: BlackSquirrelz
# Date: 2021-03-10
# Description: Tool to find IOC based on hash, ip, regular expressions and shells.

# Imports
import re
import file_handler
import logging
import requests
import hashlib
import testing.efficiency_test as profiler


@profiler.profile
def get_ip(file, ioc_file):
    """Read Text from file and regex search for IP Addreses."""
    print(f"Extracting IP Addresses from {file}")
    # Setting Regexd Pattern for IP Extraction.
    pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

    exceptions = ['0.0.0.0', '127.0.0.1', None]

    hits = []
    all_ips = []
    unique_ips = set()

    # TODO: Change to CSV for added information on IOC origin, e.g. Emotet etc.
    with open(ioc_file, 'r') as f:
        ip_iocs = [ip.strip() for ip in f]

    # Read information from Log file
    with open(file, 'r') as scan_file:
        text = [line.strip() for line in scan_file]
        text = [t.split() for t in text]

    # Search through tokenized log file
    for line in text:
        for token in line:
            ip = pattern.search(token)
            if ip is not None and ip[0] not in exceptions:
                unique_ips.add(ip[0])

    for ip in unique_ips:
        if ip not in all_ips and ip in ip_iocs:
            logging.warning(f"{file} contains IP: {ip}, this IP was found in {ioc_file}")
            info = {ip: get_geoLocaton(ip)}
            hits.append({file: info})
            all_ips.append(ip)
        elif ip not in all_ips:
            logging.info(f"{file} contains IP: {ip}, this IP was not found in {ioc_file}")
            all_ips.append(ip)

    file_handler.save_json("output/suspicious_ips", hits)


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


# Generating MD5 and SHA1 hash and comparing them to the list of known IOCs
@profiler.profile
def scan_hashes(file, ioc_hashes):
    print(f"Scanning {file}")

    # Generating the SHA1 and MD5 hashes of the inspected file
    md5hash = hashlib.md5(open(file, 'rb').read()).hexdigest()
    sha1hash = hashlib.sha1(open(file, 'rb').read()).hexdigest()

    # Comparison of MD5 and SHA1 against the Generated Hash of the file.
    with open(ioc_hashes) as hash_file:
        for line in hash_file:
            line = line.strip().lower()
            if line == md5hash or line == sha1hash:
                logging.warning(f"{file} matches known IOC \nMD5: {md5hash}\nSHA1: {sha1hash}")


# TODO: Implement shell scanner
def scan_shells(file):
    print("Scanning for shells")


# TODO: Shell Scanner
def scan_regex():
    print("Scanning Regex")

    """
        # PART THREE: REGEX Matcher
        bad_regex = []
        for entry in regex_list:
            for item in entry:
                logging.warning(f'{item["Match"]} matches pattern {item["Regex"]} in file {item["file_path"]}, line #: {item["line_number"]}!')
                bad_regex.append({'match': item["Match"], 'path': item["file_path"]})

        bad_regex_outfile = 'output\\' + str(case_number) + "_REGEX_Matches"
        file_handler.save_json(bad_regex_outfile, bad_regex)

    """

# Lookup geo location of IP
def get_geoLocaton(ip):
    """ Function to get the IP's GeoLocation"""
    source = 'https://json.geoiplookup.io/' + str(ip)
    print(source)
    logging.info(f'Requesting {source}')
    r = requests.get(source)
    ip_info = r.json()
    if r.status_code == 200:
        try:
            result = {'lat': ip_info['latitude'],
                      'long': ip_info['longitude'],
                      'country': ip_info['country_name'],
                      'source': source
                      }

            logging.info(f"{source} returned {r.status_code}")
        except:
            logging.error(f"Could not find information on {ip}, {ip_info['error']}")
            result = {'lat': 0, 'long': 0, 'country': 'UNK', 'source': source}
    return result

