# VitroBench

This repository keeps the software that is used in this project:

## 1. Communication board

1. fpga_can_bridge_source_code_pynq2.tar.xz - This archive contains the FPGA hardware abstraction files and firmware files for [Pynq-Z2 Development Board](http://www.pynq.io/board.html). Programming this dev. kit requires use of Vivado 2019.1.

2. pcb_can_bridge_shield_pynq2 - This folder contains hardware related files for the PCB board that is mounted on top of the Pynq-Z2 FPGA Board. The hardware on this folder is structured as follows:
   1. Schematic_PCB_CAN Bridge.zip - Contains schematic files for the bridge project
   2. Gerber_PCB_CAN Bridge.zip - Contains gerber files for PCB production
   3. BOM_PCB_CAN Bridge_2023-07-31.csv - Contains the bill of materials of all components soldered to the PCB
   4. PickAndPlace_PCB_CAN Bridge_2023-07-31.csv - Contains pick and place fabrication file for  industrial assembly of PCB. This file is not needed if the components are to be soldered by hand.

## 2. CAN Test Platform
​Note: Sniffing software is from [TSMaster](https://github.com/TOSUN-Shanghai/TSMaster).

1. Python programs
   1. bmw_bridge_passthru.py - This program performs a pass-through of all messages via the bridge.
   2. bmw_cas130_attack.py - This attack forces the car to stop. CAS is isolated and bridged from KCAN. Within the  program, setting (attack_type=1) stops the car when the driver starts the      car for the third time and setting (attack_type=2) stops the car when the  car is running, and a specified time duration is reached.
   3. bmw_ekp_attackBridge.py - This is an  attack on the fuel pump controller by bridging Engine ECU from PCAN. Byte  7 (D8) of message 0xAA was fuzzed when the Engine RPM is greater than  750. During the attack, EKP outputs an erratic fuel pump signal.
   4. bmw_ekp_attackInject_Burst.py - This is  an attack on the fuel pump controller by injecting messages 0xAA to PCAN.  Byte 7 (D8) of message 0xAA was fuzzed when the Engine RPM is greater than 850. During the attack, EKP outputs an erratic fuel pump signal.
   5. bmw_flooding_inject_deltatime_stealth.py - This is a flooding attack by injecting stealth messages from 0x0 to 0x1A5 to KCAN to cause a denial of service to the instrument cluster. The      attack stopped the display message 0x1A6 to reach the Instrument Cluster.
   6. bmw_floodin8g_inject_deltatime.py - This  is a flooding attack by injecting message 0x80 to KCAN to cause a denial of service to the instrument cluster. The attack stopped the display      message 0x1A6 to reach the Instrument Cluster.
   7. bmw_jbe_fuzz1_v10.py - This program  conducts a penetration test by injecting random message IDs and data from the external Diagnostic network. The workstation can monitor all the      In-Vehicle Networks (IVNs) messages to check which messages have      infiltrated the IVNs. Within the program, setting (sniff=True) will log the infiltrated messages to the file,      {'jbe_infiltrate'+date_time+'.blf'}.
   8. bmw_speed_attack1.py - This attack causes the instrument cluster to display the wrong speed. DSC is isolated and bridged from PCAN. The car runs normally until the attack speed of      40km/h. Thereafter, the speed in message 0x1A6 is randomly set.
   9. bmw_speed_attack2.py - This causes the instrument cluster to display the wrong speed. DSC is isolated and bridged from PCAN. The car runs normally until the attack speed of 10 km/h. Thereafter, the speed message 0x1A6 is incremented by 2/3 of the actual increased speed and clipped at the maximum speed of 35 km/h.
