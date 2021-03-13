#!/usr/bin/venv python3
# -*- coding: utf-8 -*-
# ioc_scanner_test.py

# Author: BlackSquirrelz
# Date: 2021-03-10
# Description: Script to get IP Addresses from Files, and compares them to known IOCs.

# Unit Testing for IOC Scanner.

# Import Statements
from unittest import TestCase, main
import ioc_scanner as iocs
from os import path


class IOCSTest(TestCase):
    """
    IOC Processor Tests
    """

    def test_get_ip_function(self):
        test_file = 'test_directory/test_2/ABC.log'
        result = iocs.get_ip(test_file)
        self.assertIsInstance(result, dict, "Dictionary requirement not met.")

    def test_default_ioc_directory(self):
        self.assertTrue(path.exists('iocs/ioc_hashes.txt'), "Default Hash IOC is empty.")
        self.assertTrue(path.exists('iocs/ioc_ip.txt'), "Default IP IOC is empty.")
        self.assertTrue(path.exists('iocs/ioc_regex.txt'), "Default REGEX IOC is empty.")
        self.assertTrue(path.exists('iocs/ioc_shells.txt'), "Default SHELLS IOC is empty.")

    def test_generic_regex_function(self):
        test_file ='test_directory/test_2/ABC.log'
        default_regex_file = 'iocs/ioc_regex.txt'
        result = iocs.generic_regex(default_regex_file, test_file)
        self.assertIsInstance(result, dict, "Dictionary requirement not met.")


