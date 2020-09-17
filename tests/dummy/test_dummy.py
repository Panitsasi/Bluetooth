#!/usr/bin/env python

""" Test suite """

from __future__ import print_function

import unittest

import core.config as config
from core.logging_utils import *

log = logging.getLogger(__name__)

class TestDummy(unittest.TestCase):
    """ Negative Tests for dummy"""
    
    def setUp(self):  
        c = config.loadConfig()
        self.comPortNRF = c['TESTBED']['COM_PORT_NRF']
        self.advertiser_address = c['TESTBED']['ADVERTISER_ADDRESS']

        self.master_address = '5d:36:ac:90:0b:22'
        self.access_address = 0x9a328370

        log.info('Advertiser Address: ' + self.advertiser_address.upper())


    def tearDown(self):
        pass


    def test_dummy_001(self):
        """"Dummy 001
        Attack Type: CWE-119"""
        log.info("Test dummy 001")

    def test_dummy_002(self):
        """"Dummy 002
        Attack Type: CWE-119"""
        log.info("Test dummy 002")

    def test_dummy_003(self):
        """"Dummy 003
        Attack Type: CWE-119"""
        log.info("Test dummy 003")
        self.fail("Just")
