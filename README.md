# zwiftpktmon
A Python port of the C# ZwiftPacketMonitor project which monitors Zwift UDP packets.  

This project implements a TCP and UDP packet monitor for the Zwift cycling simulator. It listens for packets on a specific port of a local network adapter, and when found, deserializes the payload and dispatches events that can be consumed by the caller.  It uses the asyncio standard library to allow the packet parsing activities to not interfere with the event consumer.

NOTE: Because this utilizes a network packet capture to intercept the UDP packets, your system may require this code to run using elevated privileges.  This is definitely required on MacOS.

### Requirements ###

- Requires Python version 3.10 or higher

- Uses the project pcapy-ng as its interface to the Pcap-API.  The Pcap-API exists natively on MacOS and Linux but not on Windows.
On Windows, the Npcap packet capture library must be installed.  Npcap is available here: https://npcap.com/dist/npcap-1.60.exe

- The pcapy-ng library is written in Cython at must be compiled for each environment.  Currently, two environments have been pre-compiled and supported: 
   - Windows 10+ (64bit AMD; Intel might work but untested)
   - MacOS 10.13+ (High Sierra)

## Setup ##

pip install zwiftpktmon

There are some example scripts in the .\tests folder:

- test_harness.py: A simple script allowing network selection and event logging.
- test_harness_ui.py: A simple UI based upon PySimpleGui.  To use this you must pip install PySimpleGui first.






