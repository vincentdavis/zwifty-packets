'''
Packet sniffer in python using the pcapy python library
'''

import socket
from struct import *
import pcapy
from zpm.protobuf import zwift_messages_pb2 as zwift_message

def main():
  
    # list all devices
    devices = pcapy.findalldevs();

    # If no devices were found print an error
    if (len(devices) < 1):
        print("No devices were found on this machine");
        return;
        

    print("");
    print("The following devices are available on this machine:");
    print("----------------------------------------------------");
    print();

    i = 0;
    for d in devices:
        print("{0}) {1}".format(i, d))
        i+=1
   
    print("");
    selection = input("-- Please choose a device to capture: ");

    i = int(selection);

    if (i >= 0 and i < len(devices)):
        print("Starting capture of device {0}".format(devices[i]));

        '''
        open device
        # Arguments here are:
        #   device
        #   snaplen (maximum number of bytes to capture _per_packet_)
        #   promiscious mode (1 for true)
        #   timeout (in milliseconds)
        '''
        cap = pcapy.open_live(devices[i], 65536, 1, 0)
        cap.setfilter("udp port 3022 or tcp port 3023");

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
    try:
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
              # print('Data : ' + str(data))

              # print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(
              #     length) + ' Checksum : ' + str(checksum))
              try:
                if(source_port == 3022):

                  player_state = zwift_message.ServerToClient()
                  player_state.ParseFromString(data)
                  print("incomingPlayerState: {0}".format(player_state))
                  
                elif(dest_port == 3022):

                  # Outgoing packets *may* have some a metadata header that's not part of the protobuf.
                  # This is sort of a magic number at the moment -- not sure if the first byte is coincidentally 0x06, 
                  # or if the header (if there is one) is always 5 bytes long
                  skip = 5;
  
                  if (data[skip] == 0x08):
                      # NOOP, as the protobuf payload looks like it starts after the initial skip estimate
                      pass
                  elif (data[0] == 0x08):
                      # protobuf payload starts at the beginning
                      skip = 0;
                  else:
                      # Use the first byte as an indicator of how far into the payload we need to look
                      # in order to find the beginning of the protobuf
                      skip = data[0] - 1;
  
                  # bypass skipped bytes and trim off last 4
                  data = data[skip:len(data) - 4]
  
                  player_state = zwift_message.ClientToServer()
                  player_state.ParseFromString(data)
                  print("outgoingPlayerState: {0}".format(player_state))

              except Exception as e:
                print("Exception :", str(e))



          # some other IP packet like IGMP
          else:
              pass
    except Exception as e: print("Exception", str(e))


if __name__ == "__main__":
    main()
