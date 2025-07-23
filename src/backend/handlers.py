

from protocols import ARP_OPCODE
from parsers import *



def IPv4_Handler(eth, data):
    ip = parseIpV4Address(data)
    print('\n-- IPV4 Packet --')
    print(f"IPV{ip['version']} | packet:  {ip['source_ip']} -> {ip['destination_ip']}")
    handler = IP_Handlers.get(ip['protocol'], handle_unknown_ip)
    handler(ip, ip['data'])
 

def TCP_Handler(ip, data):
    tcp_seg = parse_tcp_segment(data)
    print('\n-- TCP Segment --')
    print(f"TCP | source port {tcp_seg['source_port']} -> {tcp_seg['destination_port']}")
    print(f"Seq: {tcp_seg['sequence']}, Ack: {tcp_seg['acknowledgement']}")


def UDP_Handler(ip, data):
    udp_seg = parse_udp_segment(data)
    print('\n-- UDP Segment --')
    print(f"UDP | source port {udp_seg['source_port']} -> destination port {udp_seg['destination_port']}")


def ARP_Handler(eth, data):
    arp_pack = parse_arp_packet(data)
    arp_opcode = ARP_OPCODE.get(arp_pack['opcode'], f'unknow({arp_pack["opcode"]})') 
    print('\n-- ARP Packet --') 
    print(f"ARP | source MAC {eth['source_mac']} -> {eth['destination_mac']}")
    
    if arp_opcode == 'request':     
        print(f"ARP Request: Who has {arp_pack['target_IP']}? Tell {arp_pack['sender_IP']}")
    elif arp_opcode == 'reply':
        print(f"ARP Reply: {arp_pack['sender_IP']} is at {eth['source_mac']}")
    else : 
        print("Unrecognized ARP OP_Code")


def IPv6_Handler(eth, data):
    ipv6 = parseIpV6Address(data)
    print('\n-- IPV6 Packet --')
    print(f"IPV{ipv6['version']} | packet:  {ipv6['source_ip']} -> {ipv6['destination_ip']}")
    handler = IPv6_Handlers.get(ipv6['next_header'], handle_unknown_ip)
    handler(ipv6, ipv6['data'])
   
def ICMP_Handler(ip, data):
    icmp = parse_ICMP(data)
    print('\n-- ICMP Message --')
    print(f"ICMP{icmp['Type']} | packet:  {ip['source_ip']} -> {ip['destination_ip']}")

def ICMPv6_Handler(ip, data):
    icmp = parse_ICMPv6(data)
    print('\n-- ICMP Message --')
    print(f"ICMP{icmp['ICMP_Type']} | packet:  {ip['source_ip']} -> {ip['destination_ip']}")
    handler = ICMPv6_Handlers.get(icmp['ICMP_Type'], handle_unknown_ICMP_type)
    handler(icmp)

def ICMP_solicitation_Handler(icmp):
    print(f"{icmp['ICMP_Type']} Neighbor Solicitation")

def ICMP_advertisement_Handler(icmp):
    print(f"{icmp['ICMP_Type']} Neighbor Advertisement")



def handle_unknown_eth(eth, data):
    print(f"Unknown Ethernet protocol: {eth['protocol']}")

def handle_unknown_ip(ip, data):
    print(f"Unknown IP-level protocol: {ip.get('protocol')}")

def handle_unknown_ICMP_type(icmp, data):
    print("Unknown ICMP type")




ETHERTYPE_Handlers = {
        0x0800: IPv4_Handler,
        0x0806: ARP_Handler,
        0x86DD: IPv6_Handler,
        }

IP_Handlers = {
        1: ICMP_Handler,
        6: TCP_Handler,
        17: UDP_Handler,
        } 

IPv6_Handlers = {
        6: TCP_Handler,
        17: UDP_Handler,
        58: ICMPv6_Handler,
        }

ICMPv6_Handlers = {
        #128: ICMP_echo_Handler,
        #129: ICMP_echo_Handler,
        135: ICMP_solicitation_Handler,
        136: ICMP_advertisement_Handler,
        }




