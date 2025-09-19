

import socket
import struct

def getMacAddr(bytes_addr):
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

    hardware_type, proto_type, hardware_length, proto_length, opcode, sender_MAC,sender_IP, target_MAC,target_IP = struct.unpack("!HHBBH6s4s6s4s", data[:28])
    
    return {
            'hardware_type': hardware_type,
            'proto_type': proto_type,
            'hardware_length': hardware_length,
            'protocol_length': proto_length,
            'opcode': opcode,
            'sender_IP': socket.inet_ntoa(sender_IP),
            'target_IP': socket.inet_ntoa(target_IP),
            'sender_MAC': getMacAddr(sender_MAC),
            'target_MAC': getMacAddr(target_MAC),
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
            'code': code,
            'data': data[2:]
                }





def is_HTTP_Request(text):
    return not text.startswith("HTTP/")




def parse_HTTP_Request(lines):
    
    
    first_line = lines[0].split(' ')   
    if not lines or len(lines[0].split(' ')) < 3:
        return {'error': 'Invalid HTTP request line'}
    
    headers = {}
    for line in lines[1:]:
        if line == '':
            break
        elif ': ' in line:
            key, value = line.split(': ', 1)
            headers[key.lower()] = value

    return{
        'method': first_line[0],
        'path': first_line[1],
        'version': first_line[2],
        'host': headers.get('host', 'N/A'),
        'user_agent': headers.get('user-agent', 'N/A'),
        'content_type': headers.get('content-type', 'N/A'),
        'content_length': headers.get('content-length', 'N/A')
    }

def parse_HTTP_Reply(lines):
    
    if not lines or len(lines[0].split(' ')) < 3:
        return {'error': 'Invalid HTTP request line'}

    try:
        version, status, reason = lines[0].split(' ', 2)
    except ValueError:
        return {'error': 'Malformed status line'}
   
    headers = {}
    for line in lines[1:]: 
        if line == '':
            break
        elif ': ' in line:
            key, value = line.split(': ', 1)
            headers[key.lower()] = value

    return {
        'version': version,
        'status': status,
        'reason': reason,
        'content_type': headers.get('content-type', 'N/A'),
        'location': headers.get('location', 'N/A')
    }


def read_dns_name(data, offset):

    labels = []
    jumps = 0
    max_jumps = 10
    original_offset = offset
    
    while offset < len(data):
        length = data[offset]

        if (length & 0xC0) == 0xC0: #if pointer
            if offset + 1 >= len(data):
                raise ValueError("Truncated dns message")
            
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            suffix_labels, _ = read_dns_name(data, pointer)
            jumps +=1
            if labels:
                return '.'.join(labels) + '.' + suffix_labels, offset+2
            else:
                return suffix_labels, offset+2
        

        elif length == 0:
            offset+=1
            break


        else:
            offset += 1
            if offset + length > len(data):
                break

            label = data[offset:offset+length]
            
            try:
                labels.append(label.decode('ascii'))
            except UnicodeDecodeError:
                labels.append(repr(label))

            offset += length


    return '.'.join(labels), offset
             
    



def parse_DNS(data):
    transaction_id, flags = struct.unpack('!HH', data[:4])
    qr = flags >> 15
    opcode = (flags >> 11) & 0x0F
    rcode = flags & 0x0F
    nbrquestions, answer_RRs, authority_RRs, additional_RRs = struct.unpack('!HHHH', data[4:12])
    
    questions = []
    offset = 12

    for _ in range(nbrquestions):
        qname, offset = read_dns_name(data, offset) 
        if offset + 4 > len(data):
            break
        
        qtype,qclass = struct.unpack('!HH', data[offset:offset+4])
        offset += 4

        questions.append({'qname': qname, 'qtype': qtype, 'qclass':qclass})

    answers = []

    for _ in range(answer_RRs):
        aname, offset = read_dns_name(data, offset)
        if offset + 10 > len(data):
            break

        rrtype, rrclass, ttl, rdlength = struct.unpack('!HHIH', data[offset : offset+10]) 
        offset += 10

        if offset + rdlength > len(data):
            raise ValueError("truncated dns message")

        rdata = data[offset: offset + rdlength]
        offset += rdlength
        answers.append({'name': aname, 'rrtype': rrtype, 'rrclass': rrclass, 'ttl': ttl, 'rdlength': rdlength, 'rdata': rdata})



    return {
        'transaction_id': hex(transaction_id),
        'flags': hex(flags),
        'qr': qr,
        'opcode': opcode,
        'rcode': rcode,
        'nbrquestions': nbrquestions,
        'answer_RRs': answer_RRs,
        'authority_RRs': authority_RRs,
        'additional_RRs': additional_RRs,
        'questions': questions,
        'answers': answers
    }


def parse_DHCP(data):
    opcode, hardware_type, hardware_addr_len, nbrhops, transaction_id = struct.unpack('!BBBB4s', data[:8])
    flags, = struct.unpack('!H', data[8:10])
    ciaddr, yiaddr, siaddr, giaddr, chaddr = struct.unpack('!4s4s4s4s6s', data[10:32])

    option = []
    offset = 240

    while offset < len(data):
        option_type = data[offset]
        offset += 1
        if option_type == 255:
            break
        if option_type == 0:
            continue

        option_len = data[offset]
        offset += 1
        option_data = data[offset: offset + option_len]
        option.append({'option_type': option_type, 'option_len': option_len, 'option_data': option_data})
        offset += option_len


    return {
        'opcode': opcode,
        'hardware_type': hardware_type,
        'hardware_addr_len': hardware_addr_len,
        'nbrhops': nbrhops,
        'transaction_id': hex(transaction_id),
        'flags': flags,
        'client_ip': socket.inet_ntoa(ciaddr),
        'your_ip': socket.inet_ntoa(yiaddr),
        'server_ip': socket.inet_ntoa(siaddr),
        'gateway_ip': socket.inet_ntoa(giaddr),
        'client_mac': getMacAddr(chaddr),
        'options': option 
    }




























