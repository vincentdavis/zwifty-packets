# zwiftpktmon
A Python port of the C# ZwiftPacketMonitor project which monitors Zwift UDP packets

This project implements a TCP and UDP packet monitor for the Zwift cycling simulator. It listens for packets on a specific port of a local network adapter, and when found, deserializes the payload and dispatches events that can be consumed by the caller.

NOTE: Because this utilizes a network packet capture to intercept the UDP packets, your system may require this code to run using elevated privileges.

### Requirements ###

 * Requires Python version 3.10 or higher

Uses the project pcapy-ng as its interface to the Pcap-API.  The Pcap-API exists natively on MacOS and Linux but not on Windows.
On Windows, the Npcap packet capture library must be installed (available here: https://npcap.com/dist/npcap-1.60.exe)

## Setup ##

pip install zwiftpktmon

### Quick start ###

Grab the latest stable python version

### Requirements ###

 * A Python interpreter. Versions 2.1.3 and newer are known to work.
 * A C++ compiler. GCC G++ 2.95, as well as Microsoft Visual Studio
   6.0, are known to work.
 * Libpcap 0.7.2 or newer. Windows user are best to check WinPcap 3.0
   or newer.
 * A recent release of Pcapy.


pip install -r requriement.txt

### Monitor ###

python ZwiftPacketMonitor.py
This project implements a TCP and UDP packet monitor for the Zwift cycling simulator. It listens for packets on a specific port of a local network adapter, and when found, deserializes the payload and dispatches events that can be consumed by the caller.

NOTE: Because this utilizes a network packet capture to intercept the UDP packets, your system may require this code to run using elevated privileges.

