#/usr/bin/python

import scapy.all as scapy

def scan(ip_address):
    #Create a broadcast ARP packet
    arp_message = scapy.ARP(pdst=ip_address)
    ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_arp_packet = ether_frame/arp_message
    #Scan the LAN for presence of hosts
    (success, failures) = scapy.srp(broadcast_arp_packet, timeout=1, verbose=False)
    host_list = [ {"mac": host.hwsrc, "ip": host.psrc} for entry in success for host in entry ]
    return host_list

def print_result(result):
    #print the result
    print("\nipv4 address" + "\t\t" + "mac address" + "\n-----------------------------------------")
    for item in result:
        print(item["ip"] + "\t\t" + item["mac"])
    print("\n")
print_result(scan("10.0.2.0/24"))


