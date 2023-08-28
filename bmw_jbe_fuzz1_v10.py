#!/usr/bin/env python3

# *** Import libraries
from os import set_blocking
import sys
import signal
import queue
from custom_layers.bmw_merged import SignalHeader   # Import custom user functions
from bmw_gui_v10 import gui_start                   # GUI
from datetime import datetime
from can import BLFWriter
from threading import Thread
from scapy.contrib.cansocket import CANSocket
from time import sleep
from scapy.layers.can import CAN
from random import randint
from can import rc as can_rc
can_rc['interface'] = 'socketcan_ctypes'

# *** Global variables

# Arrays for GUI
k_ids_array, p_ids_array, f_ids_array = {}, {}, {}
bridge_net_array, bridge_ecu_array = {}, {}
k_raw_pkts, p_raw_pkts, f_raw_pkts = [], [], []

# Display
sniff = False    # set False for no sniffing, i.e. no logging
disp = False     # set False for no display for good latency
pkt_rate = 1     # display packet update rate: every 1 pkt update rate -> spikes about every 100 messages

# *** Classes


class BLFMsg(object):
    def __init__(self):
        self.channel = 0
        self.dlc = 0
        self.arbitration_id: 0
        self.timestamp: 0
        self.id_type = False
        self.is_extended_id = False
        self.is_remote_frame = False
        self.is_fd = False
        self.bitrate_switch = False
        self.error_state_indicator = False
        self.is_error_frame = False


# Initialise Linux CAN Socket - Note BLF_id = id+1
p_soc, p_id, p_rate = 'can_5', 1, 500000        # id=0 (pcan)
f_soc, f_id, f_rate = 'can_4', 2, 500000        # id=1 (fcan)
k_soc, k_id, k_rate = 'can_6', 3, 100000        # id=2 (kcan)
# id=3 (bridge), b_rate depends on which network
b_soc, b_id = 'can_7', 4
d_soc, d_id, d_rate = 'can0', 5, 500000         # id=4 (dcan)

# Open Linux CAN Socket - Note BLF_id = id+1
pcan_socket = CANSocket(channel=p_soc, bitrate=p_rate,
                        receive_own_messages=True)           # pcan
fcan_socket = CANSocket(channel=f_soc, bitrate=f_rate,
                        receive_own_messages=True)           # fcan
kcan_socket = CANSocket(channel=k_soc, bitrate=k_rate,
                        receive_own_messages=True)           # kcan

# jbe monitor socket
dcan_mon = CANSocket(channel=d_soc, bitrate=500000,
                     receive_own_messages=True)              # dcan monitor

# jbe dcan fuzz
dcan_tx = CANSocket(channel=d_soc, bitrate=500000,
                    receive_own_messages=False)              # dcan transmit

# *** Define signal handler to stop this program


def signal_handler(sig, frame):

    print('\nYou pressed Ctrl+C!')

    if sniff:
        # Clear queues
        q_cm.join()
        q_cn.join()
        q_ce.join()

        # Stop writer
        writer_cm.stop()
        writer_ce.stop()
        writer_cn.stop()

        print("Sniffer stopped")
    sys.exit(0)                                 # End program

# *** Define workers for queue - writetofile


def worker_cm():
    msg = BLFMsg()
    while True:
        [pckt, can_nbr] = q_cm.get()
        msg.channel = can_nbr
        msg.arbitration_id = pckt.identifier
        msg.timestamp = pckt.time
        msg.dlc = pckt.length
        msg.data = pckt.data
        writer_cm.on_message_received(msg)
        q_cm.task_done()


def worker_cn():
    msg = BLFMsg()
    while True:
        [pckt, can_nbr] = q_cn.get()
        msg.channel = can_nbr
        msg.arbitration_id = pckt.identifier
        msg.timestamp = pckt.time
        msg.dlc = pckt.length
        msg.data = pckt.data
        writer_cn.on_message_received(msg)
        q_cn.task_done()


def worker_ce():
    msg = BLFMsg()
    while True:
        [pckt, can_nbr] = q_ce.get()
        msg.channel = can_nbr
        msg.arbitration_id = pckt.identifier
        msg.timestamp = pckt.time
        msg.dlc = pckt.length
        msg.data = pckt.data
        writer_ce.on_message_received(msg)
        q_ce.task_done()


def msg_display(pkt, ids_array, raw_pkts, pkt_counter):

    # Try to decoded CAN frame from generated DBC layer (bmw_merged.py)
    decoded_pkt = SignalHeader(bytes(pkt))

    # Fill IDs array (ids_array)
    if pkt.identifier not in ids_array:
        ids_array[pkt.identifier] = [
            decoded_pkt.summary(), decoded_pkt, pkt, 1]
    else:
        count = ids_array[pkt.identifier][3]
        ids_array[pkt.identifier] = [
            decoded_pkt.summary(), decoded_pkt, pkt, count + 1]

    # # Fill temporary array of packets, limit to 18 (raw_pkts_array)
    raw_pkts.append([pkt_counter, pkt.identifier, bytes(pkt)])
    if len(raw_pkts) > 18:
        raw_pkts.pop(0)

# *** Sniffers


def p_sniffer():
    pcan_counter = 0
    while True:
        # Receive can frame
        pkt = pcan_socket.recv()
        q_cm.put_nowait([pkt.identifier, pkt.time, pkt.length, pkt.data, p_id])
        pcan_counter += 1                                       # Increase packet counter
        if pcan_counter % pkt_rate == 0 and disp:  # Setting for update every pkt
            msg_display(pkt, p_ids_array, p_raw_pkts, pcan_counter)


def f_sniffer():
    fcan_counter = 0
    while True:
        # Receive can frame
        pkt = fcan_socket.recv()
        q_cm.put_nowait([pkt.identifier, pkt.time, pkt.length, pkt.data, f_id])
        fcan_counter += 1                                       # Increase packet counter
        if fcan_counter % pkt_rate == 0 and disp:  # Setting for update every pkt
            msg_display(pkt, f_ids_array, f_raw_pkts, fcan_counter)


def k_sniffer():
    kcan_counter = 0
    while True:
        # Receive can frame
        pkt = kcan_socket.recv()
        q_cm.put_nowait([pkt.identifier, pkt.time, pkt.length, pkt.data, k_id])
        kcan_counter += 1                                       # Increase packet counter
        if kcan_counter % pkt_rate == 0 and disp:  # Setting for update every pkt
            msg_display(pkt, k_ids_array, k_raw_pkts, kcan_counter)

# *** Define jbe monitoring thread


def jbe_mon():

    pkt_counter = 0
    while True:

        # ======== monitor =========
        # Receive can frame
        d_pkt = dcan_mon.recv()

        # Increase packet counter
        pkt_counter += 1

        # Try to decoded CAN frame from generated DBC layer (bmw_merged.py)
        decoded_pkt = SignalHeader(bytes(d_pkt))

        # Fill IDs array (ids_array)
        if d_pkt.identifier not in bridge_net_array:
            bridge_net_array[d_pkt.identifier] = [
                decoded_pkt.summary(), decoded_pkt, d_pkt, 1]
        else:
            count = bridge_net_array[d_pkt.identifier][3]
            bridge_net_array[d_pkt.identifier] = [
                decoded_pkt.summary(), decoded_pkt, d_pkt, count + 1]

        # Check data matching
        if d_pkt.identifier != 0x130:
            # if d_pkt.identifier == 0x130:
            d = bytearray(d_pkt.data)
            d_len = len(d)
            id = d_pkt.identifier
            if d_pkt.identifier in p_ids_array:
                pkt = p_ids_array[d_pkt.identifier][2]
                dm = bytearray(pkt.data)
                dm_len = len(dm)
                if dm_len == d_len:
                    d_match = True
                    for i in range(d_len):
                        if d[i] != dm[i]:
                            d_match = False
                    if d_match:
                        if id not in bridge_ecu_array:
                            bridge_ecu_array[id] = [
                                decoded_pkt.summary(), decoded_pkt, d_pkt, 1]
                        else:
                            count = bridge_ecu_array[id][3]
                            bridge_ecu_array[id] = [
                                decoded_pkt.summary(), decoded_pkt, d_pkt, count + 1]
                        if sniff:
                            q_ce.put([pkt, p_id])
            id = d_pkt.identifier+0x2000
            if d_pkt.identifier in f_ids_array:
                pkt = f_ids_array[d_pkt.identifier][2]
                dm = bytearray(pkt.data)
                dm_len = len(dm)
                if dm_len == d_len:
                    d_match = True
                    for i in range(d_len):
                        if d[i] != dm[i]:
                            d_match = False
                    if d_match:
                        if id not in bridge_ecu_array:
                            bridge_ecu_array[id] = [
                                decoded_pkt.summary(), decoded_pkt, d_pkt, 1]
                        else:
                            count = bridge_ecu_array[id][3]
                            bridge_ecu_array[id] = [
                                decoded_pkt.summary(), decoded_pkt, d_pkt, count + 1]
                        if sniff:
                            q_ce.put([pkt, f_id])
            id = d_pkt.identifier+0x3000
            if d_pkt.identifier in k_ids_array:
                pkt = k_ids_array[d_pkt.identifier][2]
                dm = bytearray(pkt.data)
                dm_len = len(dm)
                if dm_len == d_len:
                    d_match = True
                    for i in range(d_len):
                        if d[i] != dm[i]:
                            d_match = False
                    if d_match:
                        if id not in bridge_ecu_array:
                            bridge_ecu_array[id] = [
                                decoded_pkt.summary(), decoded_pkt, d_pkt, 1]
                        else:
                            count = bridge_ecu_array[id][3]
                            bridge_ecu_array[id] = [
                                decoded_pkt.summary(), decoded_pkt, d_pkt, count + 1]
                        if sniff:
                            q_ce.put([pkt, k_id])

# *** Define jbe inject thread


def jbe_inject():

    pkt_counter = 0
    while True:

        id = randint(0x600, 0x6ff)
        # id = 0x130
        if True:
            # for id in range(0x500,0x600):
            numByte = randint(2, 8)
            d = bytearray(numByte)
            for i in range(numByte):
                d[i] = randint(0, 255)
            d[1] = numByte-2                # Using some protocol guessing
            d_pkt = CAN(identifier=id, length=numByte, data=d)

            # Increase packet counter
            pkt_counter += 1

            for i in range(5):
                # tx packet
                dcan_tx.send(d_pkt)
                if sniff:
                    q_cn.put([d_pkt, d_id])

                # delay for next transmit
                sleep(0.033)

# **** Main Program ***


# Install signal for program exit
signal.signal(signal.SIGINT, signal_handler)

try:

    # GUI interface
    if disp:
        gui_start(k_ids_array, p_ids_array, f_ids_array, k_raw_pkts,
                  p_raw_pkts, f_raw_pkts, bridge_net_array, bridge_ecu_array)

    if sniff:
        # logging files name
        now = datetime.now()
        date_time = now.strftime("%Y%m%d%H%M")
        dataFolder = './data/'
        cmFile = dataFolder+'cm'+date_time+'.blf'
        jbe_dcan = dataFolder+'jbe_dcan'+date_time+'.blf'
        jbe_infiltrate = dataFolder+'jbe_infiltrate'+date_time+'.blf'

        # Initialise BLF writer
        writer_cm = BLFWriter(cmFile)
        writer_cn = BLFWriter(jbe_dcan)
        writer_ce = BLFWriter(jbe_infiltrate)
        writer_cm.start_timestamp = 0
        writer_cn.start_timestamp = 0
        writer_ce.start_timestamp = 0

        # Initialise queue to write to file
        q_cm = queue.Queue()
        q_cn = queue.Queue()
        q_ce = queue.Queue()

        # Turn-on the workers thread to write to file
        Thread(target=worker_cm, daemon=True).start()
        Thread(target=worker_cn, daemon=True).start()
        Thread(target=worker_ce, daemon=True).start()

        # Start sniffer thread
        Thread(target=p_sniffer, daemon=True).start()
        Thread(target=f_sniffer, daemon=True).start()
        Thread(target=k_sniffer, daemon=True).start()

    # # Start bridge_net
    Thread(target=jbe_mon, daemon=True).start()

    # # Start bridge_ecu
    Thread(target=jbe_inject, daemon=True).start()

    while True:
        sleep(50000)

except KeyboardInterrupt:
    print("\nSniffer stopped")
