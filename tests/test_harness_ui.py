"""
test_harness_ui.py

Used to test functionality

Uses the PySimpleGui framework
"""

import asyncio
import logging

import PySimpleGUI as sg
import pcapy

import context  # adds base directory to path
# import zpm.async_monitor
from zpm.async_monitor import Monitor
import zpm.events as events

Log: logging.Logger = None
window = None


async def main():
    def __init__(cls):
        pass

    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    global Log
    Log = logging.getLogger(__name__)
    Log.info(f"Process starting")

    # list all devices
    devices = pcapy.findalldevs();

    layout = [
        [sg.Listbox(devices, size=(60, 5), select_mode=sg.LISTBOX_SELECT_MODE_SINGLE, key='-DEVICES-')],
        [sg.Multiline(size=(60, 10), write_only=True, echo_stdout_stderr=True, reroute_stdout=True)],
        [sg.Text("Timeouts: "), sg.Text("", key='-TIMEOUT_COUNT-')],
        [sg.Button('Go'), sg.Button('Nothing'), sg.Button('Exit')]
    ]

    global window
    window = sg.Window('Zwift Packet Monitor Test', layout)

    m = Monitor()

    m.RegisterEventSubscriber(events.ZwiftEvent.TimeoutWaitingForPacketEvent, OnTimeoutWaitingForPacketEvent)
    m.RegisterEventSubscriber(events.ZwiftEvent.IncomingRiderStateEvent, OnIncomingRiderStateEvent)
    m.RegisterEventSubscriber(events.ZwiftEvent.OutgoingRiderStateEvent, OnOutgoingRiderStateEvent)

    while True:  # Event Loop
        Log.debug("in event loop")
        event, values = window.read(timeout=500, timeout_key="-TIMEOUT-")
        if event == sg.WIN_CLOSED or event == 'Exit':
            await Monitor().StopCaptureAsync()
            break
        if event == 'Go':
            d = window['-DEVICES-'].get()
            if len(d) == 1:
                print(f'Device {d[0]} selected.')
                # Start the capture.  Don't await as StartCaptureAsync won't return until capture is stopped.
                asyncio.create_task(Monitor().StartCaptureAsync(d[0]))
        elif event == '-TEST-':
            msg = values['-TEST-']
            print(f'{msg}')
        elif event == '-TIMEOUT-':  # window event loop timeout
            await asyncio.sleep(0.1)
    window.close()


timeout_count = 0


def OnTimeoutWaitingForPacketEvent(eventargs):
    Log.debug("Event: OnTimeoutWaitingForPacketEvent")
    global timeout_count
    timeout_count += 1
    t: sg.Text = window['-TIMEOUT_COUNT-']
    t.update(value=str(timeout_count))
    print("timeout")


def OnIncomingRiderStateEvent(eventargs):
    Log.debug(f"Event: OnIncomingRiderStateEvent")


def OnOutgoingRiderStateEvent(eventargs):
    Log.debug(f"Event: OnOutgoingRiderStateEvent")


if __name__ == "__main__":
    asyncio.run(main())
