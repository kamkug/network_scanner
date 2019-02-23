#/usr/bin/python

import scapy.all as scapy
import optparse



def provide_address():
    #read command line arguments and provide the address
    parser = optparse.OptionParser()
    parser.add_option("-i", "--ip_address", dest="addr", help="Provide an ip/network address, ex: 192.168.1.1")
    parser.add_option("-m", "--mask", dest="mask", help="Provide the mask, ex: /32")
    return parser.parse_args()[0]

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


address = provide_address()

print_result(scan(address.addr + address.mask))



