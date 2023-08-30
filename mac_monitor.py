"""
This script monitors a network for a given mac address and reports the status
"""
import argparse
import subprocess
import time
import xml.etree.ElementTree as ET

import requests
from statemachine import StateMachine, State


def mac_status(net, mac):
    """
    Get the status of a mac address on a network

    :param net: The network name (e.g. 192.168.0.1/24)
    :param mac: The mac address to monitor
    :return: either 'present' or 'absent'
    """
    process = subprocess.Popen(['sudo', 'nmap', '-oX', '/tmp/nmap.xml', '-sn', net],
                               stdout=subprocess.PIPE)
    process.wait()

    tree = ET.parse('/tmp/nmap.xml')
    for node in tree.iter('address'):
        if node.attrib['addrtype'] == 'mac' and node.attrib['addr'] == mac:
            return 'present'
    return 'absent'


class MacAddressMonitoringMachine(StateMachine):
    """
    A state machine that monitors a network for the presence of a given mac address
    """
    # Define the states and transitions
    # The initial state is 'present'
    # The 'absent' state is used when the mac address is not found
    # The 'present' state is used when the mac address is found
    # The 'cycle' state is used to transition between the 'present' and 'absent' states
    present = State(initial=True)
    absent = State()
    cycle = (present.to(absent) | absent.to(present))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--network",
                        action="store",
                        required=True,
                        dest="network_address",
                        help="The network address")

    parser.add_argument("--mac",
                        action="store",
                        required=True,
                        dest="mac_address",
                        help="The mac address")

    parser.add_argument("--url",
                        action="store",
                        required=True,
                        dest="rest_url",
                        help="The REST API URL")

    parser.add_argument("--sleep",
                        action="store",
                        required=False,
                        default=47,
                        dest="sleep_time",
                        help="Sleep time between checks")

    args = parser.parse_args()

    sm = MacAddressMonitoringMachine()

    # Set the state machine to match the current mac status
    if mac_status(args.network_address, args.mac_address) != 'present':
        sm.send('cycle')

    # print(sm.current_state.id)

    current = sm.current_state.id

    while True:
        sample = mac_status(args.network_address, args.mac_address)
        if sample != current:
            # print(f'{current}->{sample}')
            sm.send('cycle')
            current = sample
            rest_call = args.rest_url + sample
            resp = requests.post(rest_call, headers={'content-type': 'application/json'})
            if resp.status_code != 200:
                raise RuntimeError(f'POST failed with status code {resp.status_code}')

        time.sleep(args.sleep_time)


if __name__ == '__main__':
    main()
