import socket
import json
import asyncio
import websockets
from datetime import datetime
import parsers

HOST = "localhost"
PORT = 8765

async def packet_sniffer(websocket):
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        print("Raw socket created successfully")
    except PermissionError:
        print("Permission denied. Please run as root/administrator")
        await websocket.send(json.dumps({"error": "Permission denied. Run as administrator."}, default=str))
        return
    except Exception as e:
        print(f"Error creating socket: {e}")
        await websocket.send(json.dumps({"error": f"Socket error: {e}"}, default=str))
        return
    
    EXCLUDE_LOOPBACK = True
    EXCLUDE_WEBSOCKET_PORT = True
    WEBSOCKET_PORT = 8765
    
    LOOPBACK_IPS = {'127.0.0.1'}
    print(f"🔍 Filtering out loopback traffic and WebSocket port {WEBSOCKET_PORT}")
    
    while True:
        try:
            raw_data, _ = conn.recvfrom(65535)
            packet_out = {"timestamp": datetime.now().isoformat()}
            should_send = True
            # Parse Ethernet frame
            eth = parsers.parse_ethernet_frame(raw_data)
            packet_out["ethernet"] = eth
            protocol = eth['protocol']
            payload = eth['data']
            
            if protocol == 0x0800:  # IPv4
                ipv4 = parsers.parseIpV4Address(payload)
                packet_out["IPv4"] = ipv4
                ipv4_protocol = ipv4['protocol']
                ipv4_payload = ipv4['data']
    
                if EXCLUDE_LOOPBACK and (ipv4["source_ip"] in LOOPBACK_IPS or ipv4["destination_ip"] in LOOPBACK_IPS):
                    should_send = False
                    continue
                
                if ipv4_protocol == 6:  # TCP
                    tcp = parsers.parse_tcp_segment(ipv4_payload)
                    packet_out["TCP"] = tcp
                    
                    try:
                        try:
                            text = tcp['data'].decode('UTF-8')
                        except UnicodeDecodeError:
                            text = tcp['data'].decode('iso-8859-1')
                        
                        lines = text.split("\r\n")
                        if lines and lines[0]:
                            if parsers.is_HTTP_Request(lines[0]):
                                parsedHTTP = parsers.parse_HTTP_Request(lines)
                                if 'method' in parsedHTTP and 'path' in parsedHTTP and 'version' in parsedHTTP:
                                    packet_out["HTTP"] = parsedHTTP
                            else:
                                parsedHTTP = parsers.parse_HTTP_Reply(lines)
                                if 'version' in parsedHTTP and 'status' in parsedHTTP and 'reason' in parsedHTTP:
                                    packet_out["HTTP"] = parsedHTTP
                    except Exception as e:
                        print(f"HTTP parsing error: {e}")
                        
                elif ipv4_protocol == 17:  # UDP
                    udp = parsers.parse_udp_segment(ipv4_payload)
                    packet_out["UDP"] = udp
                    source_port = udp['source_port']
                    destination_port = udp['destination_port']
                    
                    if source_port == 53 or destination_port == 53:  # DNS
                        try:
                            dns = parsers.parse_DNS(udp['data'])
                            packet_out["DNS"] = dns
                        except Exception as e:
                            print(f"DNS parsing error: {e}")
                    
                    if source_port in (67, 68) or destination_port in (67, 68):  # DHCP
                        try:
                            dhcp = parsers.parse_DHCP(udp['data'])
                            packet_out["DHCP"] = dhcp
                        except Exception as e:
                            print(f"DHCP parsing error: {e}")
                            
                elif ipv4_protocol == 1:  # ICMP
                    try:
                        icmp = parsers.parse_ICMP(ipv4_payload)
                        packet_out["ICMP"] = icmp
                    except Exception as e:
                        print(f"ICMP parsing error: {e}")
                        
            elif protocol == 0x86DD:  # IPv6
                try:
                    ipv6 = parsers.parseIpV6Address(payload)  
                    packet_out["IPv6"] = ipv6  
                    ipv6_next_header = ipv6['next_header']
                    ipv6_payload = ipv6['data']
                
                    if ipv6_next_header == 58:  # ICMPv6
                        icmpv6 = parsers.parse_ICMPv6(ipv6_payload)
                        packet_out["ICMPv6"] = icmpv6  
                except Exception as e:
                    print(f"IPv6 parsing error: {e}")
            
            elif protocol == 0x0806:  # ARP
                try:
                    arp = parsers.parse_arp_packet(payload)
                    packet_out["ARP"] = arp 
                except Exception as e:
                    print(f"ARP parsing error: {e}")
            
            await websocket.send(json.dumps(packet_out, default=str))
            
        except websockets.exceptions.ConnectionClosed:
            print("WebSocket connection closed")
            break
        except Exception as e:
            print(f"Error processing packet: {e}")
            continue

async def handler(websocket, path):
    print(f"Client connected: {websocket.remote_address}")
    try:
        await packet_sniffer(websocket)
    except Exception as e:
        print(f"Handler error: {e}")
    finally:
        print(f"Client disconnected: {websocket.remote_address}")

async def main():
    print(f"Starting Sniffy packet sniffer bridge on ws://{HOST}:{PORT}")
    print("Note: This requires administrator/root privileges to capture packets")
    
    async with websockets.serve(handler, HOST, PORT):
        print(f"Sniffer bridge running on ws://{HOST}:{PORT}")
        await asyncio.Future()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutting down sniffer bridge...")
    except Exception as e:
        print(f"Error starting server: {e}")
        print("Make sure you're running with administrator privileges!")


