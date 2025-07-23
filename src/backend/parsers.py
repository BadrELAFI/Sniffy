


import socket
import struct

def getMacAddr(bytes_addr):
    #return ':'.join('%02x' % b for b in bytes_addr)
    return ':'.join(f'{b:02x}' for b in bytes_addr)

def parse_ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return {
        'destination_mac': getMacAddr(dest_mac),
        'source_mac': getMacAddr(src_mac),
        'protocol': proto,
        'data': data[14:]
    }

def parseIpV4Address(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 0x0F) * 4
    ttl, proto, src_IP, dest_IP = struct.unpack('!8xBB2x4s4s', data[:20])
    return {
        'version': version,
        'header_length': header_length,
        'ttl': ttl,
        'protocol': proto,
        'source_ip': socket.inet_ntoa(src_IP),
        'destination_ip': socket.inet_ntoa(dest_IP),
        'data': data[header_length:]
    }

def parseIpV6Address(data):
    
    if len(data) < 40: 
        return{'error': 'Ipv6 packet is too short'}

    first_byte, second_byte, flow_label_right = struct.unpack('!BBH', data[:4])
    
    version = first_byte >> 4
    trafic = ((first_byte & 0x0F) << 4) | (second_byte >> 4)
    flow_label = ((second_byte & 0x0F) << 16) | flow_label_right
    next_header = struct.unpack('!B', data[6:7])[0]
    src_IP = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dest_IP = socket.inet_ntop(socket.AF_INET6, data[24:40])
    
    return {
            'version': version,
            'trafic': trafic,
            'flow_label': flow_label,
            'next_header': next_header,
            'source_ip': src_IP,
            'destination_ip': dest_IP,
            'data': data[40:]
            }



def parse_tcp_segment(data):
    
    src_port, dest_port, seq, ack, offset_reserved_flags = struct.unpack('!HHLLH', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    
    return {
        'source_port': src_port,
        'destination_port': dest_port,
        'sequence': seq,
        'acknowledgement': ack,
        'data': data[offset:]
    }

def parse_udp_segment(data):
    
    src_port, dest_port, length = struct.unpack("!HHH", data[:6])
    
    return {
        'source_port': src_port,
        'destination_port': dest_port,
        'data': data[8:]
    }


def parse_arp_packet(data):
    
    if len(data) < 28:
        return {'error': 'ARP packet too short'}

    hardware_type, proto_type, hardware_length, proto_length, opcode, sender_IP, target_IP = struct.unpack("!HHBBH6x4s6x4s", data[:28])
    
    return {
            'hardware_type': hardware_type,
            'proto_type': proto_type,
            'hardware_length': hardware_length,
            'protocol_length': proto_length,
            'opcode': opcode,
            'sender_IP': socket.inet_ntoa(sender_IP),
            'target_IP': socket.inet_ntoa(target_IP),
            'data': data[28:]
            }

def parse_ICMP(data):
    if len(data) < 8:
        return {'error': 'ICMP packet is too short'}
    icmptype, code, identif, seq = struct.unpack('!BB2xHH', data[:8])
    return {
            'Type': icmptype,
            'code': code,
            'identification': identif,
            'sequence': seq,
            'data': data[12:]
            }

def parse_ICMPv6(data):
    if len(data) < 8:
        return {'error': 'ICMP packet is too short'}

    icmp_type, code = struct.unpack('!BB', data[:2])
    return {
            'ICMP_Type': icmp_type,
            'code': code
            }
















