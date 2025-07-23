
from handlers import ETHERTYPE_Handlers, handle_unknown_eth
import socket
from parsers import parse_ethernet_frame

def sniff():
    
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)
        eth = parse_ethernet_frame(raw_data)
        eth_handler = ETHERTYPE_Handlers.get(eth['protocol'], handle_unknown_eth)
        eth_handler(eth, eth['data'])




if __name__ == '__main__':
    
    try:
        print("Sniffy (prototype):")
        sniff()
    
    except KeyboardInterrupt:
        print("\nProgram terminated.")
    
    except PermissionError:
        print("\nUser not authorized (try running as sudo/admin).")











































