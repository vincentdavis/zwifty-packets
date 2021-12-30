'''
Packet sniffer in python using the pcapy python library
'''

import socket
from struct import *
import pcapy


def main():
  # list all devices
  devices = pcapy.findalldevs()

  # ask user to enter device name to sniff
  print("Available devices are :")

  for d in devices:
    print(d)

  dev = input("Enter device name to sniff : ")

  print("Sniffing device " + dev)

  '''
  open device
  # Arguments here are:
  #   device
  #   snaplen (maximum number of bytes to capture _per_packet_)
  #   promiscious mode (1 for true)
  #   timeout (in milliseconds)
  '''
  cap = pcapy.open_live(dev, 65536, 1, 0)

  # start sniffing packets
  while (1):
    (header, packet) = cap.next()
    # print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))
    parse_packet(packet)

# Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr(a):
        b = "{}:{}:{}:{}:{}:{}".format (str(a[0]), str(a[1]), str(a[2]), str(a[3]),
                                                          str(a[4]), str(a[5]))
        return b


# function to parse a packet
def parse_packet(packet):
    # parse ethernet header
    eth_length = 14

    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH', eth_header)

    eth_protocol = socket.ntohs(eth[2])

    # print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(
    #     eth_protocol))


    # Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8:
        # Parse IP header
        # take first 20 characters for the ip header
        ip_header = packet[eth_length:20 + eth_length]

        # now unpack them :)
        iph = unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);

        # print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(
        #     protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))


        # UDP packets
        if protocol == 17:
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u + 8]

            # now unpack them :)
            udph = unpack('!HHHH', udp_header)

            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]
            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size

            # get data from the packet
            data = packet[h_size:]
            print('Data : ' + str(data))

            # print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(
            #     length) + ' Checksum : ' + str(checksum))
            try:
              if(source_port == 3022):
                print("incomingPlayerState")
                print('Data : ' + str(data))
              elif(dest_port == 3022):
                print("outgoingPlayerState")
                print('Data : ' + str(data))
            except Exception as e:
              print("Exception :", str(e))



        # some other IP packet like IGMP
        else:
            pass


if __name__ == "__main__":
    main()
