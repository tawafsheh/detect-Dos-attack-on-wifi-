# !/usr/bin/python

from __future__ import print_function 

from scapy.all import *



ssid=input("enter your AP name... \n")

bssid=""

deauth_packet_counter = 0

disass_packet_counter = 0


def detect_deauth(packet): 

	global ssid 

	global bssid

	global deauth_packet_counter 

	global disass_packet_counter 


	if packet.haslayer(Dot11Deauth):

		if packet.addr2 == bssid:

			deauth_packet_counter = deauth_packet_counter + 1

			print("\r [+] deauthentication packets are detected : " + str(deauth_packet_counter) , end=" ")	

			print( "againest ssid : "+  ssid+ "  ")

			if (deauth_packet_counter > 400) and (deauth_packet_counter % 100 ==0): 

				print("...................................................................................................................Careful!!!!......Danger!!!!")

				# considering the deauthintaction is the only danger we worry about after 400 count then to each 100 packet will send a warning message... 


	if packet.type==0x00 and packet.subtype==0x0c:

		disass_packet_counter = disass_packet_counter + 1

		print("\r [+] disassociation packets are detected : " + str(disass_packet_counter) , end=" ")	

		print( "againest ssid : "+  ssid+ "  ")


	if packet.haslayer(Dot11Beacon):

		if packet.info == ssid:

			bssid = packet.addr2
	

sniff(iface="wlan0mon",prn=detect_deauth,count=0)
#make sure to set the right interface for the script to work. 