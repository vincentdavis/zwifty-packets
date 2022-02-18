import socket
import struct
import logging
import threading
import traceback

import pcapy
from circuits import Event, Component

from zpm.protobuf import zwift_messages_pb2 as zwift_message
import zpm.events as zwift_event
#print(f"monitor.py {dir()}")


class terminate(Event):
    """terminate Event - used internally to stop worker thread"""

class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

class Monitor(metaclass=Singleton):
    """
    Main entry point into package.
    
    """
    
    # The default Zwift UDP data port
    ZWIFT_UDP_PORT = 3022;

    # The default Zwift TCP data port
    ZWIFT_TCP_PORT = 3023;

    # Default read timeout for packet capture
    READ_TIMEOUT = 1000;

    # Packet direction
    UNKNOWN_PACKET = 0;
    INCOMING_PACKET = 1;
    OUTGOING_PACKET = 2;


    def __init__(self):
        Monitor.logger = logging.getLogger(__name__)
        self.event_mgr = EventManager()
        self.thread = None
        self.pcap_device = None


    def RegisterEventListener(self, listener:Component):
        '''
        Helper method to allow external event listeners.

        Listener classes need to inherit from circuits.Component
        '''
        
        # enable listener event handling
        listener.register(self.event_mgr)
        Monitor.logger.debug(f'Event listener {listener.__class__} added.')


    def StartCaptureAsync(self, networkInterface):
        '''
        Start the Zwift Packet Monitor capture thread.
        '''
        Monitor.logger.debug(f'Attempting to start packet capture on {networkInterface}, current thread: {threading.get_native_id()}')

        '''
        #   network
        #   snaplen (maximum number of bytes to capture _per_packet_)
        #   promiscious mode (1 for true)
        #   timeout (in milliseconds)
        '''
        self.pcap_device = pcapy.open_live(networkInterface, 65536, 1, Monitor.READ_TIMEOUT);
        self.pcap_device.setfilter("udp port {0} or tcp port {1}".format(Monitor.ZWIFT_UDP_PORT, Monitor.ZWIFT_TCP_PORT));
        # note use of trailing comma in args due to tuple of one
        self.thread = threading.Thread(target=self.event_mgr.Worker, args=(self.pcap_device,), daemon=False)
        self.thread.start()


    def StopCaptureAsync(self):
        Monitor.logger.debug(f'Attempting to stop packet capture, current thread: {threading.get_native_id()}');

        # Tell the worker thread to shut itself down clean
        self.event_mgr.StopWorker()

        # wait for the shutdown
        self.thread.join()
        self.thread = None

        # clean up
        if (self.pcap_device is not None):
            self.pcap_device.close()
            self.pcap_device = None


    ## Convert a string of 6 characters of ethernet address into a dash separated hex string
    #def _eth_addr(self, a):
    #        b = "{}:{}:{}:{}:{}:{}".format (str(a[0]), str(a[1]), str(a[2]), str(a[3]),
    #                                                          str(a[4]), str(a[5]))
    #        return b




class EventManager(Component):
    """
    This class manages two threads:
        1) The circuits library event management thread.  This dispatches fired messages to the listeners.
        2) The Zwift Packet Monitor (or pcapy) thread.  This reads and forwards packets to the PacketManager class.
    """

    def __init__(self):
        super().__init__()

        EventManager.logger = logging.getLogger(__name__)

        # create PacketManager and enable event handling        
        self.packet_mgr = PacketManager()
        self.packet_mgr.register(self)


    def started(self, *args):
        EventManager.logger.debug("EventManager started")


    #def IncomingRiderStateEvent(self, eventargs: RiderStateEventArgs):
    #    EventManager.logger.debug("IncomingRiderStateEvent: {}".format(str(eventargs)))


    #def OutgoingRiderStateEvent(self, eventargs: RiderStateEventArgs):
    #    EventManager.logger.debug("OutgoingRiderStateEvent: {}".format(str(eventargs)))


    def StopWorker(self):
        self.processing_enabled = False
        EventManager.logger.debug("StopWorker - enabled: {}".format(str(self.processing_enabled)))


    def Worker(self, pcap_device):
        EventManager.logger.debug(f"Worker thread starting, worker thread: {threading.get_native_id()}")

        self.processing_enabled = True

        # begin circuits event processing loop
        self.start() 

        while(self.processing_enabled):
            # receive packet
            (header, eth_packet) = pcap_device.next()

            if (len(eth_packet) > 0):
                self.packet_mgr.OnPacketArrival(eth_packet)
            else:
                self.fire(zwift_event.TimeoutWaitingForPacketEvent())
                #EventManager.logger.debug("Timeout waiting for packet")

        self.fire(terminate())

        EventManager.logger.debug(f"Waiting for circuits threads to finish, worker thread: {threading.get_native_id()}")
        self.join()

        EventManager.logger.debug("Worker thread ended.")


    def TimeoutWaitingForPacketEvent(self):
        """Occurs when pcap_device.next() returns empty"""
        #EventManager.logger.debug(f"TimeoutWaitingForPacketEvent, circuits thread: {threading.get_native_id()}")

    def terminate(self):
        self.stop() # end event processing loop


class PacketManager(Component):
    """
    This class manages the initial interpretation of an ethernet (IP) packet.

    Packets will be a mix of TCP and UDP protocols and must be decifered upon arrival.

    TCP will be inbound only and sometimes multiple packets have to be assembled into a single buffer of data.
    UDP can be inbound or outbound but the outbound contains the PlayerState data for the local rider.

    Once packet assembly has been accomplished they are deserialized by the protobuf framework.  This yields the actual messages!

    The protobuf messages contain player state and other updates.  We take these messages and abstract them into events (using the circuits package).
    """

    def __init__(self):
        super().__init__()

        PacketManager.logger = logging.getLogger(__name__)
        self._pkt_assembly_buffer = None
        self._pkt_assembly_buffer_len = 0
        self._pkt_assembly_complete = False


    def OnPacketArrival(self, eth_packet):
        """
        Examine the packet's ethernet header to determine it's protocol.
        
        TCP gets some extra attention while UDP flows through (well kinda).
        """

        # If received packet is empty, quit
        if (len(eth_packet) == 0):
            return

        try:
            direction = None;

            # parse ethernet header
            eth_length = 14
            eth_header = eth_packet[:eth_length]
            eth = struct.unpack('!6s6sH', eth_header)

            # convert from network to host byte order
            eth_protocol = socket.ntohs(eth[2])

            #print('Destination MAC : ' + self.eth_addr(packet[0:6]) + ' Source MAC : ' + self.eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))

            # Parse IP packets, IP Protocol number = 8
            if (eth_protocol == 8):
                # Parse IP header
                # take first 20 characters for the ip header
                ip_header = eth_packet[eth_length:20 + eth_length]

                # now unpack them :)
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

                version_ihl = iph[0]
                version = version_ihl >> 4
                ihl = version_ihl & 0xF

                iph_length = ihl * 4

                ttl = iph[5]
                protocol = iph[6]
                s_addr = socket.inet_ntoa(iph[8]);
                d_addr = socket.inet_ntoa(iph[9]);

                #print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' 
                #        + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))

                if (protocol == 6): # TCP
                    header_start_pos = iph_length + eth_length
                    packet_data = eth_packet[header_start_pos:]

                    self._assemble_tcp_packet(packet_data)

                elif (protocol == 17): # UDP

                    direction = Monitor.UNKNOWN_PACKET

                    u = iph_length + eth_length
                    udph_length = 8
                    udp_header = eth_packet[u:u + 8]

                    # now unpack them :)
                    udph = struct.unpack('!HHHH', udp_header)

                    source_port = udph[0]
                    dest_port = udph[1]
                    length = udph[2]
                    checksum = udph[3]
                    h_size = eth_length + iph_length + udph_length
                    data_size = len(eth_packet) - h_size

                    # get data from the packet
                    packet_data = eth_packet[h_size:]

                    #print('packet_data : ' + str(packet_data))
                    #print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' 
                    #      + str(length) + ' Checksum : ' + str(checksum))

                    if(source_port == Monitor.ZWIFT_UDP_PORT):

                        direction = Monitor.INCOMING_PACKET
                  
                    elif(dest_port == Monitor.ZWIFT_UDP_PORT):
                            
                        # Outgoing packets *may* have some a metadata header that's not part of the protobuf.
                        # This is sort of a magic number at the moment -- not sure if the first byte is coincidentally 0x06, 
                        # or if the header (if there is one) is always 5 bytes long

                        if (packet_data[5] == 0x08):
                            # the protobuf payload looks like it starts after the initial skip estimate
                            # bypass skipped bytes and trim off last 4
                            packet_data = packet_data[5:len(packet_data) - 4]

                            direction = Monitor.OUTGOING_PACKET

                    self._deserialize_and_dispatch(packet_data, direction)

        except Exception as e: 
            PacketManager.logger.error("Unable to parse packet: {}".format(e))


    def _assemble_tcp_packet(self, packet_data):
        """
        Handles the reassembly of multiple fragmented TCP packets into a single buffer.

        Many thanks to @jeroni7100 for figuring out the packet reassembly magic!
        """
        try:

            tcp_header = packet_data[:20] # grab first 20 bytes which is the minimum tcp header size

            #print("tcp_header: {}".format([hex(c) for c in tcp_header]))

            # unpack the header
            tcph = struct.unpack('!HHIIBBHHH', tcp_header)

            source_port = tcph[0]

            if (source_port == Monitor.ZWIFT_TCP_PORT):
                # decode the rest of the tcp header
                dest_port = tcph[1]
                sequence = tcph[2]
                ack_nbr = tcph[3]
                data_offset = tcph[4] >> 4 # toss the low order bits, this is the number of 32 bit words
                data_offset *= 4 # account for 32 bit word size (4 bytes each)
                bit_flags = tcph[5]

                is_ack = (bit_flags & 0b00010000 > 0)
                is_push = (bit_flags & 0b00001000 > 0)

                tcp_data = packet_data[data_offset:]

                #print('Source Port: ' + str(source_port) + ', Dest Port: ' + str(dest_port) + ', Sequence: ' 
                #    + str(sequence) + ', AckNbr: ' + str(ack_nbr) + ', Offset: ' + str(data_offset) + ', is_ack: ' + str(is_ack) + ', is_push: ' + str(is_push)
                #    + ', tcp_data len: ' + str(len(tcp_data))
                #    )

                if (is_push and is_ack and self._pkt_assembly_buffer is None):
                    # no reassembly required
                    self._pkt_assembly_buffer = tcp_data
                    self._pkt_assembly_buffer_len = len(tcp_data)
                    self._pkt_assembly_complete = True

                    #PacketManager.logger.debug("Complete packet - Length: {}, Push: {}, Ack: {}".format(len(self.pkt_assembly_buffer), str(is_push), str(is_ack)))
                
                elif (is_push and is_ack):
                    # last packet in sequence
                    self._pkt_assembly_buffer += tcp_data
                    self._pkt_assembly_buffer_len += len(tcp_data)
                    self._pkt_assembly_complete = True

                    #PacketManager.logger.debug("Fragmented sequence finished - Length: {}, Push: {}, Ack: {}".format(len(self._pkt_assembly_buffer), str(is_push), str(is_ack)))

                elif (is_ack and self._pkt_assembly_buffer is None):
                    # first packet in sequence
                    self._pkt_assembly_buffer = tcp_data
                    self._pkt_assembly_buffer_len = len(tcp_data)

                    #PacketManager.logger.debug("Fragmented packet started - Length: {}, Push: {}, Ack: {}".format(len(self._pkt_assembly_buffer), str(is_push), str(is_ack)))

                elif (is_ack):
                    # middle packet in sequence
                    self._pkt_assembly_buffer += tcp_data
                    self._pkt_assembly_buffer_len += len(tcp_data)

                    #PacketManager.logger.debug("Fragmented packet continued - Length: {}, Push: {}, Ack: {}".format(len(self._pkt_assembly_buffer), str(is_push), str(is_ack)))

                if (self._pkt_assembly_complete and len(self._pkt_assembly_buffer) > 0):
                    # All done, call deserialize and reset for next set of packets
                    #PacketManager.logger.debug("Packet completed! - Length: {}, Push: {}, Ack: {}".format(str(self.pkt_assembly_buffer_len), str(is_push), str(is_ack)))

                    # Break apart any concatenated payloads
                    offset = 0
                    length = 0

                    while (offset < self._pkt_assembly_buffer_len):

                        tcph = struct.unpack('!H', self._pkt_assembly_buffer[:2])
                        length = tcph[0]

                        #print("break apart: len:{} {}".format(length, [hex(c) for c in self.pkt_assembly_buffer[offset + 2:20]]))
                         
                        if (offset + length < self._pkt_assembly_buffer_len):
                            payload = self._pkt_assembly_buffer[offset + 2:length + 2]
                            if (len(payload) > 0):
                                self._deserialize_and_dispatch(payload, Monitor.INCOMING_PACKET)

                        offset += 2 + length
                        length = 0

                    self._reset_pkt_assembly()

        except Exception as e: 
            PacketManager.logger.error("Unable to assemble packet: {}".format(traceback.format_exc()))


    def _reset_pkt_assembly(self):
        self._pkt_assembly_buffer = None
        self._pkt_assembly_buffer_len = 0
        self._pkt_assembly_complete = False

    
    def _deserialize_and_dispatch(self, packet_data, direction):
        """
        Takes the prepared packet data and deserializes it into protobufs.

        Events are then raised for state and update notifications.
        """

        # If we don't have any data to deserialize, quit
        if (len(packet_data) == 0):
            return

        try:

            # Depending on the direction, we need to use different protobuf parsers
            if (direction == Monitor.OUTGOING_PACKET):
                protobuf = zwift_message.ClientToServer()
                protobuf.ParseFromString(packet_data)

                pl_state = protobuf.state

                if (pl_state is not None):
                    self.fire(zwift_event.OutgoingRiderStateEvent(zwift_event.RiderStateEventArgs.InitFromProtobuf(pl_state)))

            elif (direction == Monitor.INCOMING_PACKET):

                #print("packet_data: {}".format([hex(c) for c in packet_data[:20]]))

                protobuf = zwift_message.ServerToClient()
                protobuf.ParseFromString(packet_data)

                # Dispatch each player state individually
                for pl_state in protobuf.player_states:
                    if (pl_state is not None):
                        self.fire(zwift_event.IncomingRiderStateEvent(zwift_event.RiderStateEventArgs.InitFromProtobuf(pl_state)))

                # Dispatch event positions if available
                if (protobuf.event_positions is not None):
                    pass

                # Dispatch player updates individually
                for pl_update in protobuf.player_updates:
                    try:
                        #print("player_update tag: {0}".format(pl_update.tag3))
                        if (pl_update.tag3 == 4): # OnIncomingRideOnGivenEvent
                            rideon = zwift_message.RideOn()
                            rideon.ParseFromString(pl_update.payload)
                            #PacketManager.logger.debug("OnIncomingRideOnGivenEvent-4: %s", str(rideon))
                            self.fire(zwift_event.RiderRideOnEvent(zwift_event.RiderRideOnEventArgs.InitFromProtobuf(rideon)))

                        elif (pl_update.tag3 == 5): # OnIncomingChatMessageEvent
                            chat = zwift_message.Chat()
                            chat.ParseFromString(pl_update.payload)
                            #PacketManager.logger.debug("OnIncomingChatMessageEvent-5: %s", str(chat))
                            self.fire(zwift_event.RiderChatEvent(zwift_event.RiderChatEventArgs.InitFromProtobuf(chat)))

                        elif (pl_update.tag3 == 105): # OnIncomingPlayerEnteredWorldEvent
                            pew = zwift_message.Payload105()
                            pew.ParseFromString(pl_update.payload)
                            #PacketManager.logger.debug("OnIncomingPlayerEnteredWorldEvent-105: %s", str(pew))
                            self.fire(zwift_event.RiderEnteredWorldEvent(zwift_event.RiderEnteredWorldEventArgs.InitFromProtobuf(pew)))

                        elif (pl_update.tag3 == 3): # OnIncomingPlayerTimeSyncEvent
                            ts = zwift_message.TimeSync()
                            ts.ParseFromString(pl_update.payload)
                            #PacketManager.logger.debug("OnIncomingPlayerTimeSyncEvent-3: %s", str(ts))
                            self.fire(zwift_event.RiderTimeSyncEvent(zwift_event.RiderTimeSyncEventArgs.InitFromProtobuf(ts)))

                        elif (pl_update.tag3 == 6 or pl_update.tag3 == 10): # Meetup Update/Create/Join event maybe?
                            meet = zwift_message.Meetup()
                            meet.ParseFromString(pl_update.payload)
                            #PacketManager.logger.debug("OnIncomingMeetupEvent-6or10: %s", str(meet))
                            self.fire(zwift_event.IncomingMeetupEvent(zwift_event.IncomingMeetupEventArgs.InitFromProtobuf(meet)))

                        elif (pl_update.tag3 == 102 or pl_update.tag3 == 109 or pl_update.tag3 == 110): # Haven't been able to decode these yet
                            pass
                        else:
                            PacketManager.logger.debug("Unknown player_update tag %d: %s", pl_update.tag3, str(pl_update))

                    except Exception as e:
                        PacketManager.logger.error("Exception parsing messages.player_updates: %s", str(e))

        except Exception as e: 
            PacketManager.logger.error("Exception occurred: {}".format(traceback.format_exc()))







