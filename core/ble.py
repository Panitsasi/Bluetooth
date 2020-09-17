
from __future__ import print_function

import sys

from core.logging_utils import *
from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *
# timeout lib
from timeout_lib import start_timeout, disable_timeout

from libs.scapy.layers.bluetooth4LE import BTLE_EMPTY_PDU

log = logging.getLogger(__name__)





def connect(driver, master_address, advertiser_address, access_address):

    # Internal vars
    none_count = 0
    end_connection = False
    connecting = False
    global adv_timeout_fired
    adv_timeout_fired = False

    def adv_timeout():
        global adv_timeout_fired
        log.error('Device not discovered during scan')
        adv_timeout_fired = True

    # Send scan request
    scan_req = BTLE() / BTLE_ADV() / BTLE_SCAN_REQ(
        ScanA=master_address,
        AdvA=advertiser_address)
    driver.send(scan_req)
    log.info('Scan Send')
    start_timeout('adv_timeout', 10, adv_timeout)

    while True:

        if adv_timeout_fired:
            return False

        pkt = None
        # Receive packet from the NRF52 Dongle
        data = driver.raw_receive()

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
            # Check if packet from advertised is received
            if pkt and (BTLE_SCAN_RSP in pkt) and pkt.AdvA == advertiser_address.lower():
                disable_timeout('adv_timeout')
                connecting = True

                log.info(advertiser_address.upper() + ': ' + pkt.summary()[7:] + ' Detected')
                # Send connection request to advertiser
                conn_request = BTLE() / BTLE_ADV(RxAdd=pkt.TxAdd, TxAdd=0) / BTLE_CONNECT_REQ(
                    InitA=master_address,
                    AdvA=advertiser_address,
                    AA=access_address,  # Access address (any)
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
                # Yes, we're sending raw link layer messages in Python. Don't tell anyone as this is forbidden!!!
                driver.send(conn_request)
            elif BTLE_DATA in pkt and connecting == True:
                connecting = False
                log.info('Slave Connected (L2Cap channel established)')
                return True

def disconnect(driver):
    term_ind = BTLE() / BTLE_DATA() / CtrlPDU() / LL_TERMINATE_IND()
    driver.send(term_ind)


def check_pulse_via_scan(driver, master_address, advertiser_address):

    global crash_timeout_fired
    crash_timeout_fired = False

    def crash_timeout():
        global crash_timeout_fired
        log.error('Device not discovered during scan. Presumed dead....')
        crash_timeout_fired = True

    scan_req = BTLE() / BTLE_ADV() / BTLE_SCAN_REQ(
        ScanA=master_address,
        AdvA=advertiser_address)

    # Yes, we're sending raw link layer messages in Python. Don't tell anyone as this is forbidden!!!
    log.info('Waiting activity from ' + advertiser_address)
    driver.send(scan_req)
    start_timeout('crash_timeout', 7, crash_timeout)

    # Internal vars
    none_count = 0

    # verify alive
    while True:
        pkt = None
        # Receive packet from the NRF52 Dongle
        data = driver.raw_receive()
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
            if (BTLE_SCAN_RSP in pkt and pkt.AdvA == advertiser_address.lower()) or (BTLE_DATA in pkt):
                log.debug("Slave RX <--- " + pkt.summary()[7:])
                log.info('Still kicking!!!')
                disable_timeout('crash_timeout')
                return True

        if crash_timeout_fired:
            log.error("No activity from device. Presumed dead....")
            return False

def check_pulse_via_mtu_exchange(driver, access_address):

    global crash_timeout_fired
    crash_timeout_fired = False

    def crash_timeout():
        global crash_timeout_fired
        log.error('Device did not answer to MTU Request. Presumed dead....')
        crash_timeout_fired = True

    # Here we send a key size with 253, which is way higher than the usual 16 bytes for the pairing procedure
    att_mtu_req = BTLE(
        access_addr=access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Exchange_MTU_Request(
        mtu=247)


    # Yes, we're sending raw link layer messages in Python. Don't tell anyone as this is forbidden!!!
    log.info('Waiting for activity')
    driver.send(att_mtu_req)  # Send mtu request 1 time
    start_timeout('crash_timeout', 7, crash_timeout)

    # Internal vars
    none_count = 0

    # verify alive
    while True:
        pkt = None
        # Receive packet from the NRF52 Dongle
        data = driver.raw_receive()
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
            if ATT_Exchange_MTU_Response in pkt and pkt.access_addr == access_address:
                log.debug("Slave RX <--- " + pkt.summary()[7:])
                log.info('Still kicking!!!')
                disable_timeout('crash_timeout')
                return True


        if crash_timeout_fired:
            log.error("No activity from device. Presumed dead....")
            return False