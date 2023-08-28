#!/usr/bin/env python3

# *** Import libraries
import sys
import signal
import queue
from custom_layers.bmw_merged import SignalHeader   # Import custom user functions
from datetime import datetime
from can import BLFWriter
from threading import Thread
from scapy.contrib.cansocket import CANSocket
from scapy.layers.can import CAN
from time import sleep, time
from random import randint
from can import rc as can_rc
can_rc['interface'] = 'socketcan_ctypes'

# Initialise Linux CAN Socket - Note BLF_id = id+1
f_soc, f_id, f_rate = 'can_4', 4, 500000
p_soc, p_id, p_rate = 'can_5', 5, 500000
k_soc, k_id, k_rate = 'can_6', 6, 100000
d_soc, d_id, d_rate = 'can_7', 7, 500000

fcan_socket = CANSocket(channel=f_soc, bitrate=f_rate,
                        receive_own_messages=False)           # fcan
pcan_socket = CANSocket(channel=p_soc, bitrate=p_rate,
                        receive_own_messages=False)           # pcan
kcan_socket = CANSocket(channel=k_soc, bitrate=k_rate,
                        receive_own_messages=False)           # kcan
dcan_socket = CANSocket(channel=d_soc, bitrate=d_rate,
                        receive_own_messages=False)           # diagnostic

# Bridge parameters, b_rate depends on which network
b_soc, b_id = 'can_3', 3
net_can, net_id, net_br = p_soc, p_id, p_rate  # select pcan for testing
bridge_can, bridge_id, bridge_br = b_soc, b_id, net_br
bridge_net_socket = CANSocket(
    channel=net_can, bitrate=net_br, receive_own_messages=False)
bridge_ecu_socket = CANSocket(
    channel=bridge_can, bitrate=bridge_br, receive_own_messages=False)

# *** Define signal handler to stop this program


def signal_handler(sig, frame):

    print('\nYou pressed Ctrl+C!')
    sys.exit(0)                                 # End program

# *** Define Bridging thread for network


def bridge_net():

    pkt_counter = 0

    while True:

        # ======== in_can =========
        # Receive can frame
        pkt = bridge_ecu_socket.recv()

        # ======== out_can =========
        bridge_net_socket.send(pkt)


# *** Define Bridging thread for ECUs


def bridge_ecu():
    while True:

        # ======== in_can =========
        # Receive can frame
        pkt = bridge_net_socket.recv()

        # ======== out_can =========
        bridge_ecu_socket.send(pkt)


# **** Main Program ***


# Install signal for program exit
signal.signal(signal.SIGINT, signal_handler)

try:

    # Start bridge_net
    Thread(target=bridge_net, daemon=True).start()

    # Start bridge_ecu
    Thread(target=bridge_ecu, daemon=True).start()

    while True:
        sleep(50000)

except KeyboardInterrupt:
    print("\nSniffer stopped")
