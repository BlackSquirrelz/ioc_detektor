import sys
import os
import re
import logging
import file_handler


# Author: BlackSquirrelz
# Date: 2021-03-10
# Description: Script to get IP Addresses from Files, and compares them to known IOCs.


#TODO: Implement IOC handler for other than IP.
#https://www.geeksforgeeks.org/python-how-to-search-for-a-string-in-text-files/


def get_ip(text, file):
    """Read Text from file and regex search for IP Addreses."""
    print(f"Extracting IP Addresses from {file}")
    # Setting Regexd Pattern for IP Extraction.
    pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    index = 0
    ip_list = []

    for line in text:
        index += 1
        hit = pattern.search(line)
        if hit is not None:
            logging.info(f"Line {index} in {file} contains IP: {hit[0]}.")
            ip_list.append({'IP': hit[0], 'line_number': index, 'file_path': file})
    return ip_list


def check_ip(suspect, confirmed):
    """Checking the found IP addresses against a list of IOC IP Addresses."""
    file_handler.read_file('ioc_list.txt')
    if suspect in confirmed:
        logging.warning(f"Identified potential match {suspect}")


def generic_regex(text, file):
    print(f"Searching for regex matches in {file}")
    # Setting Regexd Pattern for matching.
    regex_list = file_handler.read_file('ioc_regex.txt')
    hit_list = []
    for regex in regex_list:
        pattern = re.compile(regex)
        index = 0

        for line in text:
            index += 1
            hit = pattern.search(line)
            if hit is not None:
                logging.info(f"Line {index} in {file} contains pattern: {hit[0]}.")
                hit_list.append({'Regex': regex, 'Match': hit[0], 'line_number': index, 'file_path': file})
    return hit_list


if __name__ == '__main__':
    """Takes arguments, root path, and case number."""
    print(25 * '-+-' + ' Start of Processing ' + 25 * '-+-')
    root = sys.argv[1]
    case_number = sys.argv[2]
    #root = "test_directory"
    logging.info(f'Setting root to: {root}')
    file_list = file_handler.get_file_paths(root_path=root)

    # PART ONE: Get all IP Addresses from the log files.
    ip_list = []
    regex_list = []
    for file in file_list:
        text = file_handler.read_file(file_path=file)
        ip_list.append(get_ip(text, file))
        regex_list.append(generic_regex(text, file))

    outfile = 'output\\Identified_IPS.txt' # Setting Variable to write an outfile.
    file_handler.save_json(outfile, ip_list)

    # PART TWO: Compare IP Addresses found to Known BAD IP Addresses
    known_bads = file_handler.read_file('ioc_list.txt')
    known_bads = [ip.strip() for ip in known_bads]
    identified_ips = file_handler.get_json('output\\Identified_IPS.txt')
    for entry in identified_ips:
        for item in entry:
            if item['IP'] in known_bads:
                print(f'\tWarning {item["IP"]} in {item["file_path"]}, line #: {item["line_number"]} matches known IOC IP!')
                logging.warning(f'Warning {item["IP"]} in {item["file_path"]}, line #: {item["line_number"]} matches known IOC IP!')

    print(len(regex_list))
    # PART THREE: REGEX Matcher
    for entry in regex_list:
        for item in entry:
            print(f'\tWarning {item["Match"]} matches pattern {item["Regex"]} in file {item["file_path"]}, line #: {item["line_number"]} line # ')
    print(25 * '-*-' + ' End of Processing ' + 25 * '-*-')
