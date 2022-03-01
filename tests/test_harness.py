"""
test_harness.py

Used to test functionality
"""
import asyncio
import logging

import pcapy

import context  # adds base directory to path
from src.zwiftpktmon.async_monitor import Monitor
import src.zwiftpktmon.events as event

print(f"test_harness.py {dir()}")

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
        Log.info("No devices were found on this machine")
        return
        

    print("")
    print("The following devices are available on this machine:")
    print("----------------------------------------------------")
    print("")

    i = 0
    for d in devices:
        print("{0}) {1}".format(i, d))
        i += 1
   
    print("")
    selection = input("-- Please choose a device to capture: ")

    i = int(selection)

    if (i >= 0 and i < len(devices)):
        # Monitor is a Singleton.  You only need to register an event handling Component class once!
        m = Monitor()
        m.register_subscriber(event.ZwiftEvent.TimeoutWaitingForPacketEvent, OnTimeoutWaitingForPacketEvent)
        m.register_subscriber(event.ZwiftEvent.IncomingRiderStateEvent, OnIncomingRiderStateEvent)
        m.register_subscriber(event.ZwiftEvent.OutgoingRiderStateEvent, OnOutgoingRiderStateEvent)

        Log.info("Starting capture of device {0}".format(devices[i]))
        asyncio.create_task(m.start_capture(devices[i]))

        # We can't wait for a keyboard press to terminate because it will block.  So just sleep for a few seconds.
        await asyncio.sleep(5.0)

        await m.stop_capture()


def OnTimeoutWaitingForPacketEvent(eventargs):
    Log.debug(f"Event: OnTimeoutWaitingForPacketEvent")


def OnIncomingRiderStateEvent(eventargs):
    Log.debug(f"Event: OnIncomingRiderStateEvent")


def OnOutgoingRiderStateEvent(eventargs):
    Log.debug(f"Event: OnOutgoingRiderStateEvent")


if __name__ == "__main__":
    asyncio.run(main())

