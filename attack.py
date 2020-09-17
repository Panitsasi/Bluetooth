#!/usr/bin/env python

""" Test suite """

#from future import print_function

import sys, unittest, shutil
import configparser
import os
import binascii

sys.path.insert(0,os.getcwd() + '/libs')
from core.logging_utils import *
from drivers.NRF52_dongle import NRF52Dongle
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.utils import wrpcap, raw

# timeout lib
from timeout_lib import start_timeout, disable_timeout, update_timeout

array = sys.argv

PYTHON_VERSION = sys.version_info[0]

if __name__ == "__main__" :

    mlogger = logger()
    mlogger.initLogger("ble_attack")

    mlogger.ble_attack.info("Loading configuration")

    log = logging.getLogger('ble_attack')

    suite = unittest.TestSuite()
    array_len = len(array)
    print "Argument length %d" % len(array)

    if array_len==2 :

        link_layer_tests=['ATT_CRUSH','CHANNEL_MAP_REQ','CONNECTION_REQUEST_CRUSH','CONNECTION_UPDATE_REQ','DOS','DUMMY','FEATURE_REQ',
            'INVALID','INVALID_SEQUENCE','LENGTH_REQ','LENGTH_REQ_single_test','LLID_DEADLOCK','PING_REQ','REJECT_IND','START_ENC_REQ']

        smp_tests=['SILENT_OVERFLOW']
        dummy_tests=['dummy']

        if array[1] in link_layer_tests:
            t = 'tests.link_layer.test_LL_' + array[1]
            print t
            a = unittest.defaultTestLoader.loadTestsFromName(t) # The files into link_layer folder starts with test_LL_
            suite.addTest(a)

        elif array[1] in smp_tests:
            t = 'tests.smp.test_smp_' + array[1]
            print t
            a = unittest.defaultTestLoader.loadTestsFromName(t) # The files into smp folder starts with test_smp
            suite.addTest(a)

        elif array[1] in dummy_tests:
            t = 'tests.dummy.test_' + array[1] # The files into dummy folder starts with test_
            print t
            a = unittest.defaultTestLoader.loadTestsFromName(t)
            suite.addTest(a)





    #Only tests in link layer folder have more than 2 tests in each file
    elif array_len>2:
        requested_tests=array[2:]
        print requested_tests

        for test in requested_tests:

            t = 'tests.link_layer.test_LL_' + array[1] + '.Test_LL_' + array[1] +'.test_link_layer_LL_' + array[1] + '_' + test
            print t
            a = unittest.defaultTestLoader.loadTestsFromName(t)
            suite.addTest(a)
    unittest.TextTestRunner().run(suite)


