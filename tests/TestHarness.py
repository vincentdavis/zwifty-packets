import logging

import pcapy
from circuits import Component

import context # adds base directory to path
import zpm
#print(f"testharness.py {dir()}")


def main():
    #logging.getLogger(__name__)
    #logging.basicConfig(format='%(levelname)s:%(asctime)s %(message)s', level=logging.INFO, datefmt='%Y-%m-%d %H:%M:%S')

    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    logger = logging.getLogger(__name__)

    logger.info(f"Process starting.")

    # list all devices
    devices = pcapy.findalldevs();

    # If no devices were found print an error
    if (len(devices) < 1):
        logger.info("No devices were found on this machine");
        return;
        

    print("");
    print("The following devices are available on this machine:");
    print("----------------------------------------------------");
    print("");

    i = 0;
    for d in devices:
        print("{0}) {1}".format(i, d))
        i+=1
   
    print("");
    selection = input("-- Please choose a device to capture: ");

    i = int(selection);

    if (i >= 0 and i < len(devices)):
        # Monitor is a Singleton.  You only need to register an event handling Component class once!
        m = zpm.Monitor();
        # Allow the Test() class to receive events
        m.RegisterEventListener(Test()) 

        logger.info("Starting capture of device {0}".format(devices[i]));
        m.StartCaptureAsync(devices[i]);

        input("--- Press <CR> to stop capture ---\n")

        m.StopCaptureAsync()


class Test(Component):
    """
    This class exists as a target for testing raised events from the circuits package
    """

    def __init__(self):
        super().__init__()

        Test.logger = logging.getLogger(__name__)

    def started(self, *args):
        """This method occurs when a class of type Component is registered"""
        Test.logger.debug(f"Test Started!")


    def TimeoutWaitingForPacketEvent(self):
        """Occurs when pcap_device.next() returns empty.  No arguments."""
        Test.logger.debug("TimeoutWaitingForPacketEvent")


    #def RiderEnteredWorldEvent(self, eventargs: RiderEnteredWorldEventArgs):
    #    Test.logger.debug("RiderEnteredWorldEvent: {}".format(str(eventargs)))

    #def RiderTimeSyncEvent(self, eventargs: RiderTimeSyncEventArgs):
    #    Test.logger.debug("RiderTimeSyncEvent: {}".format(str(eventargs)))

    #def IncomingMeetupEvent(self, eventargs: IncomingMeetupEventArgs):
    #    Test.logger.debug("IncomingMeetupEvent: {}".format(str(eventargs)))

    #def RiderRideOnEvent(self, eventargs: RiderRideOnEventArgs):
    #    Test.logger.debug("RiderRideOnEvent: {}".format(str(eventargs)))

    #def RiderChatEvent(self, eventargs: RiderChatEventArgs):
    #    Test.logger.debug("RiderChatEvent: {}".format(str(eventargs)))

    def IncomingRiderStateEvent(self, eventargs: zpm.RiderStateEventArgs):
        """This event is raised for all riders EXCEPT the client based rider"""
        Test.logger.debug("IncomingRiderStateEvent: {}".format(str(eventargs)))

    #def OutgoingRiderStateEvent(self, eventargs: RiderStateEventArgs):
        """This event is raised for the client based rider"""
        Test.logger.debug("OutgoingRiderStateEvent: {}".format(str(eventargs)))



if __name__ == "__main__":
    main()

