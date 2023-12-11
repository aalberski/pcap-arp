# Name: Adam Alberski
# ID: 112890087
# Date: 4/16/2022
import socket
import struct
import dpkt

# Opens pcap file and assigns a read object
filename = 'assignment4_my_arp.pcap'
file = open(filename, 'rb')
pcap = dpkt.pcap.Reader(file)

# Storage for request arp
request = None
# Storage for reply arp
reply = None


# Prints output by converting pulled bytes with hex, and socket for the case of ip addresses.=
def printInfo(packet):
    print('\t' * 2 + 'Hardware Type: ' + packet[14:16].hex() +
          '\n' + '\t' * 2 + 'Protocol Type: ' + packet[16:18].hex() +
          '\n' + '\t' * 2 + 'Hardware Size: ' + str(packet[18]) +
          '\n' + '\t' * 2 + 'Protocol Size: ' + str(packet[19]) +
          '\n' + '\t' * 2 + 'Opcode: ' + packet[20:22].hex() +
          '\n' + '\t' * 2 + 'Sender MAC address: ' + packet[22:28].hex(':') +
          '\n' + '\t' * 2 + 'Sender IP address: ' + socket.inet_ntoa(struct.pack('>L', int(packet[28:32].hex(), 16))) +
          '\n' + '\t' * 2 + 'Target MAC address: ' + packet[32:38].hex(':') +
          '\n' + '\t' * 2 + 'Target IP address: ' + socket.inet_ntoa(struct.pack('>L', int(packet[38:42].hex(), 16))))


if __name__ == '__main__':
    # Finds the request and reply packets
    for ts, buf in pcap:
        # Check if the current packet is an ARP and request
        if buf[12:14].hex() == '0806' and buf[20:22].hex() == '0001' and buf[0:6].hex() != 'ffffffffffff' and request is None:
            request = buf
        # Check if the current packet is an ARP and response
        elif buf[12:14].hex() == '0806' and buf[20:22].hex() == '0002' and reply is None:
            reply = buf
        # If request and reply are already found, end the search
        elif request is not None and reply is not None:
            break

    # Prints out all information and headers
    print('ARP Exchange:')
    print('\n\tARP Request:')
    printInfo(request)
    print('\n\tARP Reply:')
    printInfo(reply)
