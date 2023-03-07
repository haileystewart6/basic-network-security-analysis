import socket
import struct
import binascii

def analyze_network(host, port):
    # Create a raw socket to receive packets
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP) as s:
        s.bind((host, port))
        while True:
            # Receive a packet from the network
            packet = s.recv(65565)
            
            # Unpack the packet header to extract the source and destination addresses
            ip_header = packet[:20]
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            source_address = socket.inet_ntoa(iph[8])
            dest_address = socket.inet_ntoa(iph[9])
            
            # Print the source and destination addresses of the packet
            print("Source:", source_address)
            print("Destination:", dest_address)

if __name__ == "__main__":
    host = input("Enter the network host to listen on: ")
    port = int(input("Enter the network port to listen on: "))
    analyze_network(host, port)
