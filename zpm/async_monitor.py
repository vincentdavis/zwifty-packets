import asyncio
from collections import defaultdict
from collections.abc import Callable
from enum import Enum, auto
import logging
import socket
import struct
import traceback

import pcapy

from zpm.protobuf import zwift_messages_pb2 as pbuf
import zpm.events as event


# print(f"async_monitor.py {dir()}")

class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class ZwiftPort(Enum):
    ZWIFT_UDP_PORT = 3022
    ZWIFT_TCP_PORT = 3023


class PacketDirection(Enum):
    UNKNOWN = auto()
    INCOMING = auto()
    OUTGOING = auto()


class Monitor(metaclass=Singleton):
    """
    Main entry point into the package.
    This class is a singleton as we don't want multiple instances reading packets.
    """

    Log: logging.Logger = None

    # Default read timeout (in ms) for packet capture
    READ_TIMEOUT = 1

    def __init__(self):
        Monitor.Log = logging.getLogger(type(self).__name__)

        self._subscribers = defaultdict(list)
        self._pcapy_mgr = _PcapyManager()
        # self.thread = None
        self._pcap_device = None

    def RegisterEventSubscriber(self, event_type: event.ZwiftEvent,
                                subscriber_fn: Callable[[event.ZwiftEventArgs], None]):
        """
        Helper method to allow external event subscribers.
        Multiple callbacks can be registered for the same event.
        A single callback can only be registered once for an event.
        """
        if (event_type in self._subscribers):
            assert(subscriber_fn not in self._subscribers.get(event_type)), \
                f"Callback {subscriber_fn.__name__} is already subscribed to event {event_type.name}"

        self._subscribers[event_type].append(subscriber_fn)

    def IsEventSubscribed(self, *event_type_list: event.ZwiftEvent) -> bool:
        """
        If any event in the list is subscribed, return True.
        This allows for efficient protobuf processing.
        """
        for event_type in event_type_list:
            if (event_type in self._subscribers):
                return True

        return False

    def PostEvent(self, event_type: event.ZwiftEvent, event_data: event.ZwiftEventArgs = None):
        """
        Inform event subscribers that an event has occured.
        """
        if (event_type in self._subscribers):
            for subscriber_fn in self._subscribers[event_type]:
                try:
                    subscriber_fn(event_data)
                except:  # subscribers need to handle their own exceptions
                    Monitor.Log.error("Exception occurred: {}".format(traceback.format_exc()))

    @staticmethod
    def OnTimeoutWaitingForPacketEvent(event_data):
        Monitor.Log.debug(f'OnTimeoutWaitingForPacketEvent')

    async def StartCaptureAsync(self, networkInterface):
        """
        Start the Zwift Packet Monitor capture thread.
        """

        if (self._pcap_device is not None):
            return

        Monitor.Log.debug(
            f'Attempting to start packet capture on {networkInterface}')

        '''
        pcapy.open_live parameters:
        #   network
        #   snaplen (maximum number of bytes to capture _per_packet_)
        #   promiscuous mode (1 for true)
        #   timeout (in milliseconds)
        '''
        self._pcap_device = pcapy.open_live(networkInterface, 65536, 1, Monitor.READ_TIMEOUT)
        self._pcap_device.setfilter(
            f"udp port {ZwiftPort.ZWIFT_UDP_PORT.value} or tcp port {ZwiftPort.ZWIFT_TCP_PORT.value}")

        # Tell the worker to startup
        await self._pcapy_mgr.Worker(self._pcap_device)

        # clean up
        if (self._pcap_device is not None):
            self._pcap_device.close()
            self._pcap_device = None

    async def StopCaptureAsync(self):
        Monitor.Log.debug(f'StopCaptureAsync started')

        # Tell the worker to shut itself down clean
        await self._pcapy_mgr.StopWorker()

        Monitor.Log.debug(f'StopCaptureAsync completed')

    # def _eth_addr(self, a):
    #        b = "{}:{}:{}:{}:{}:{}".format (str(a[0]), str(a[1]), str(a[2]), str(a[3]),
    #                                                          str(a[4]), str(a[5]))
    #        return b


class _PcapyManager():
    """
    Manages the pcapy processor.  This reads and forwards packets to the PacketManager class.
    """

    Log: logging.Logger = None

    def __init__(self):
        _PcapyManager.Log = logging.getLogger(type(self).__name__)

        self._processing_enabled = False
        self._is_running = False

        # create PacketManager and enable event handling        
        self._packet_mgr = _PacketManager()

    async def StopWorker(self):
        _PcapyManager.Log.debug("StopWorker started")
        self._processing_enabled = False

        while (self._is_running):
            await asyncio.sleep(0.1)

        _PcapyManager.Log.debug("StopWorker completed")

    async def Worker(self, pcap_device):
        _PcapyManager.Log.debug(f"Worker started")

        self._processing_enabled = True
        self._is_running = True
        m = Monitor()

        while (self._processing_enabled):
            # receive packet
            (header, eth_packet) = pcap_device.next()

            if (len(eth_packet) > 0):
                self._packet_mgr.OnPacketArrival(eth_packet)
            else:
                m.PostEvent(event.ZwiftEvent.TimeoutWaitingForPacketEvent)
                # PcapyManager.Log.debug("Timeout waiting for packet")
                await asyncio.sleep(1)  # sleep one second

        self._is_running = False

        _PcapyManager.Log.debug("Worker Completed")


class _PacketManager():
    """
    This class manages the initial interpretation of an ethernet (IP) packet.

    Packets will be a mix of TCP and UDP protocols and must be deciphered upon arrival.

    TCP will be inbound only and sometimes multiple packets have to be assembled into a single buffer of data.
    UDP can be inbound or outbound but the outbound contains the PlayerState data for the local rider.

    Once packet assembly has been accomplished they are deserialized by the protobuf framework.
    This yields the actual messages!

    The protobuf messages contain player state and other updates.  We take these messages and abstract them into events.
    """

    Log: logging.Logger = None

    def __init__(self):
        _PacketManager.Log = logging.getLogger(type(self).__name__)

        self._pkt_assembly_buffer = None
        self._pkt_assembly_buffer_len = 0
        self._pkt_assembly_complete = False

    def OnPacketArrival(self, eth_packet):
        """
        Examine the packet's ethernet header to determine its protocol.
        
        TCP gets some extra attention while UDP flows through (well kinda).
        """

        # If received packet is empty, quit
        if (len(eth_packet) == 0):
            return

        try:
            # parse ethernet header
            eth_length = 14
            eth_header = eth_packet[:eth_length]
            eth = struct.unpack('!6s6sH', eth_header)

            # convert from network to host byte order
            eth_protocol = socket.ntohs(eth[2])

            # print('Destination MAC : ' + self.eth_addr(packet[0:6]) + ' Source MAC : ' + self.eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))

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

                # print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl)
                #   + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : '
                #   + str(d_addr))

                if (protocol == 6):  # TCP
                    header_start_pos = iph_length + eth_length
                    packet_data = eth_packet[header_start_pos:]

                    self._assemble_tcp_packet(packet_data)

                elif (protocol == 17):  # UDP

                    direction = PacketDirection.UNKNOWN

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

                    # print('packet_data : ' + str(packet_data))
                    # print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : '
                    #      + str(length) + ' Checksum : ' + str(checksum))

                    if (source_port == ZwiftPort.ZWIFT_UDP_PORT.value):

                        direction = PacketDirection.INCOMING

                    elif (dest_port == ZwiftPort.ZWIFT_UDP_PORT.value):

                        # Outgoing packets *may* have some a metadata header that's not part of the protobuf.
                        # This is sort of a magic number at the moment -- not sure if the first byte is coincidentally
                        #  0x06, or if the header (if there is one) is always 5 bytes long

                        if (packet_data[5] == 0x08):
                            # the protobuf payload looks like it starts after the initial skip estimate
                            # bypass skipped bytes and trim off last 4
                            packet_data = packet_data[5:len(packet_data) - 4]

                            direction = PacketDirection.OUTGOING

                    self._deserialize_and_dispatch(packet_data, direction)

        except Exception as e:
            _PacketManager.Log.error("Unable to parse packet: {}".format(e))

    def _assemble_tcp_packet(self, packet_data):
        """
        Handles the reassembly of multiple fragmented TCP packets into a single buffer.

        Many thanks to @jeroni7100 for figuring out the packet reassembly magic!
        """
        try:

            tcp_header = packet_data[:20]  # grab first 20 bytes which is the minimum tcp header size

            # print("tcp_header: {}".format([hex(c) for c in tcp_header]))

            # unpack the header
            tcph = struct.unpack('!HHIIBBHHH', tcp_header)

            source_port = tcph[0]

            if (source_port == ZwiftPort.ZWIFT_TCP_PORT.value):
                # decode the rest of the tcp header
                dest_port = tcph[1]
                sequence = tcph[2]
                ack_nbr = tcph[3]
                data_offset = tcph[4] >> 4  # toss the low order bits, this is the number of 32 bit words
                data_offset *= 4  # account for 32 bit word size (4 bytes each)
                bit_flags = tcph[5]

                is_ack = (bit_flags & 0b00010000 > 0)
                is_push = (bit_flags & 0b00001000 > 0)

                tcp_data = packet_data[data_offset:]

                # print('Source Port: ' + str(source_port) + ', Dest Port: ' + str(dest_port) + ', Sequence: '
                #    + str(sequence) + ', AckNbr: ' + str(ack_nbr) + ', Offset: ' + str(data_offset) + ', is_ack: '
                #    + str(is_ack) + ', is_push: ' + str(is_push)
                #    + ', tcp_data len: ' + str(len(tcp_data))
                #    )

                if (is_push and is_ack and self._pkt_assembly_buffer is None):
                    # no reassembly required
                    self._pkt_assembly_buffer = tcp_data
                    self._pkt_assembly_buffer_len = len(tcp_data)
                    self._pkt_assembly_complete = True

                    # PacketManager.logger.debug(
                    #   "Complete packet - Length: {}, Push: {}, Ack: {}"
                    #   .format(len(self.pkt_assembly_buffer), str(is_push), str(is_ack)))

                elif (is_push and is_ack):
                    # last packet in sequence
                    self._pkt_assembly_buffer += tcp_data
                    self._pkt_assembly_buffer_len += len(tcp_data)
                    self._pkt_assembly_complete = True

                    # PacketManager.logger.debug("Fragmented sequence finished - Length: {}, Push: {}, Ack: {}"
                    # .format(len(self._pkt_assembly_buffer), str(is_push), str(is_ack)))

                elif (is_ack and self._pkt_assembly_buffer is None):
                    # first packet in sequence
                    self._pkt_assembly_buffer = tcp_data
                    self._pkt_assembly_buffer_len = len(tcp_data)

                    # PacketManager.logger.debug("Fragmented packet started - Length: {}, Push: {}, Ack: {}"
                    #   .format(len(self._pkt_assembly_buffer), str(is_push), str(is_ack)))

                elif (is_ack):
                    # middle packet in sequence
                    self._pkt_assembly_buffer += tcp_data
                    self._pkt_assembly_buffer_len += len(tcp_data)

                    # PacketManager.logger.debug("Fragmented packet continued - Length: {}, Push: {}, Ack: {}"
                    #   .format(len(self._pkt_assembly_buffer), str(is_push), str(is_ack)))

                if (self._pkt_assembly_complete and len(self._pkt_assembly_buffer) > 0):
                    # All done, call deserialize and reset for next set of packets
                    # PacketManager.logger.debug("Packet completed! - Length: {}, Push: {}, Ack: {}"
                    #   .format(str(self.pkt_assembly_buffer_len), str(is_push), str(is_ack)))

                    # Break apart any concatenated payloads
                    offset = 0
                    length = 0

                    while (offset < self._pkt_assembly_buffer_len):

                        tcph = struct.unpack('!H', self._pkt_assembly_buffer[:2])
                        length = tcph[0]

                        # print("break apart: len:{} {}"
                        #   .format(length, [hex(c) for c in self.pkt_assembly_buffer[offset + 2:20]]))

                        if (offset + length < self._pkt_assembly_buffer_len):
                            payload = self._pkt_assembly_buffer[offset + 2:length + 2]
                            if (len(payload) > 0):
                                self._deserialize_and_dispatch(payload, PacketDirection.INCOMING)

                        offset += 2 + length
                        length = 0

                    self._reset_pkt_assembly()

        except Exception as e:
            _PacketManager.Log.error("Unable to assemble packet: {}".format(traceback.format_exc()))

    def _reset_pkt_assembly(self):
        self._pkt_assembly_buffer = None
        self._pkt_assembly_buffer_len = 0
        self._pkt_assembly_complete = False

    @staticmethod
    def _deserialize_and_dispatch(packet_data, direction: PacketDirection):
        """
        Takes the prepared packet data and deserializes it into protobufs.

        Events are then raised for state and update notifications.
        """

        # If we don't have any data to deserialize, quit
        if (len(packet_data) == 0):
            return

        m = Monitor()

        try:
            # Depending on the direction, we need to use different protobuf parsers
            if (direction == PacketDirection.OUTGOING):
                # Don't bother to parse buffer if nobody is subscribed
                if (m.IsEventSubscribed(event.ZwiftEvent.OutgoingRiderStateEvent)):
                    protobuf = pbuf.ClientToServer()
                    protobuf.ParseFromString(packet_data)

                    pl_state = protobuf.state

                    if (pl_state is not None):
                        # PacketManager.Log.debug("OnOutgoingRiderStateEvent-4: %s", str(pl_state))
                        m.PostEvent(event.ZwiftEvent.OutgoingRiderStateEvent,
                                    event.RiderStateEventArgs.InitFromProtobuf(pl_state))

            elif (direction == PacketDirection.INCOMING):
                # print("packet_data: {}".format([hex(c) for c in packet_data[:20]]))

                # Don't bother to parse buffer if nobody is subscribed
                if (m.IsEventSubscribed(
                        event.ZwiftEvent.IncomingRiderStateEvent,
                        event.ZwiftEvent.RiderRideOnEvent,
                        event.ZwiftEvent.RiderChatEvent,
                        event.ZwiftEvent.RiderEnteredWorldEvent,
                        event.ZwiftEvent.RiderTimeSyncEvent,
                        event.ZwiftEvent.IncomingMeetupEvent)):

                    protobuf = pbuf.ServerToClient()
                    protobuf.ParseFromString(packet_data)

                    # Dispatch each player state individually
                    for pl_state in protobuf.player_states:
                        if (pl_state is not None):
                            # PacketManager.Log.debug("OnIncomingRiderStateEvent-4: %s", str(pl_state))
                            m.PostEvent(event.ZwiftEvent.IncomingRiderStateEvent,
                                        event.RiderStateEventArgs.InitFromProtobuf(pl_state))

                    # Dispatch event positions if available
                    if (protobuf.event_positions is not None):
                        pass

                    # Dispatch player updates individually
                    for pl_update in protobuf.player_updates:
                        try:
                            if (pl_update.tag3 == 4):
                                # OnIncomingRideOnGivenEvent
                                msg = pbuf.RideOn()
                                msg.ParseFromString(pl_update.payload)
                                # PacketManager.Log.debug("OnIncomingRideOnGivenEvent-4: %s", str(msg))
                                m.PostEvent(event.ZwiftEvent.RiderRideOnEvent,
                                            event.RiderRideOnEventArgs.InitFromProtobuf(msg))

                            elif (pl_update.tag3 == 5):
                                # OnIncomingChatMessageEvent
                                msg = pbuf.Chat()
                                msg.ParseFromString(pl_update.payload)
                                # PacketManager.Log.debug("OnIncomingChatMessageEvent-5: %s", str(msg))
                                m.PostEvent(event.ZwiftEvent.RiderChatEvent,
                                            event.RiderChatEventArgs.InitFromProtobuf(msg))

                            elif (pl_update.tag3 == 105):
                                # OnIncomingPlayerEnteredWorldEvent
                                msg = pbuf.Payload105()
                                msg.ParseFromString(pl_update.payload)
                                # PacketManager.Log.debug("OnIncomingPlayerEnteredWorldEvent-105: %s", str(msg))
                                m.PostEvent(event.ZwiftEvent.RiderEnteredWorldEvent,
                                            event.RiderEnteredWorldEventArgs.InitFromProtobuf(msg))

                            elif (pl_update.tag3 == 3):
                                # OnIncomingPlayerTimeSyncEvent
                                msg = pbuf.TimeSync()
                                msg.ParseFromString(pl_update.payload)
                                # PacketManager.Log.debug("OnIncomingPlayerTimeSyncEvent-3: %s", str(msg))
                                m.PostEvent(event.ZwiftEvent.RiderTimeSyncEvent,
                                            event.RiderTimeSyncEventArgs.InitFromProtobuf(msg))

                            elif (pl_update.tag3 == 6 or pl_update.tag3 == 10):
                                # Meetup Update/Create/Join event maybe?
                                msg = pbuf.Meetup()
                                msg.ParseFromString(pl_update.payload)
                                # PacketManager.Log.debug("OnIncomingMeetupEvent-6or10: %s", str(msg))
                                m.PostEvent(event.ZwiftEvent.IncomingMeetupEvent,
                                            event.IncomingMeetupEventArgs.InitFromProtobuf(msg))

                            elif (pl_update.tag3 in (102, 106, 109, 110)):
                                # Haven't been able to decode these yet
                                pass
                            else:
                                _PacketManager.Log.debug("Unknown player_update tag %d: %s", pl_update.tag3,
                                                         str(pl_update))

                        except Exception as e:
                            _PacketManager.Log.error("Exception parsing messages.player_updates: %s", str(e))

        except Exception as e:
            _PacketManager.Log.error("Exception occurred: {}".format(traceback.format_exc()))


"""
The main() method here allows for quick testing
"""
Log: logging.Logger = None


async def main():
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    global Log
    Log = logging.getLogger(__name__)

    Log.info(f"Process starting.")

    # list all devices
    devices = pcapy.findalldevs()

    # If no devices were found print an error
    if (len(devices) < 1):
        Log.info("No devices were found on this machine");
        return;

    print("");
    print("The following devices are available on this machine:");
    print("----------------------------------------------------");
    print("");

    i = 0;
    for d in devices:
        print("{0}) {1}".format(i, d))
        i += 1

    print("");
    selection = input("-- Please choose a device to capture: ");

    i = int(selection);

    if (i >= 0 and i < len(devices)):
        # Monitor is a Singleton.  You only need to register an event handling Component class once!
        m = Monitor()
        m.RegisterEventSubscriber(event.ZwiftEvent.TimeoutWaitingForPacketEvent, OnTimeoutWaitingForPacketEvent)
        m.RegisterEventSubscriber(event.ZwiftEvent.IncomingRiderStateEvent, OnIncomingRiderStateEvent)
        m.RegisterEventSubscriber(event.ZwiftEvent.OutgoingRiderStateEvent, OnOutgoingRiderStateEvent)

        Log.info("Starting capture of device {0}".format(devices[i]))
        asyncio.create_task(m.StartCaptureAsync(devices[i]))

        # We can't wait for a keyboard press to terminate because it will block.  So just sleep for a few seconds.
        await asyncio.sleep(5.0)

        await m.StopCaptureAsync()


def OnTimeoutWaitingForPacketEvent(eventargs):
    Log.debug(f"Event: OnTimeoutWaitingForPacketEvent")


def OnIncomingRiderStateEvent(eventargs):
    Log.debug(f"Event: OnIncomingRiderStateEvent")


def OnOutgoingRiderStateEvent(eventargs):
    Log.debug(f"Event: OnOutgoingRiderStateEvent")


if __name__ == "__main__":
    asyncio.run(main())
