import pcapy
import logging
from context import zpm
from zpm.monitor import Monitor

def main():
    #logging.getLogger(__name__)
    #logging.basicConfig(format='%(levelname)s:%(asctime)s %(message)s', level=logging.INFO, datefmt='%Y-%m-%d %H:%M:%S')

    logging.basicConfig(level=logging.INFO, format='%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    logger = logging.getLogger(__name__)


    logger.info("Process starting.")

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
        m = Monitor();
        m.StartCaptureAsync(devices[i]);



if __name__ == "__main__":
    main()

