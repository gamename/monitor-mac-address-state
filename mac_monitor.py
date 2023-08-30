import argparse
import subprocess
import time
import xml.etree.ElementTree as ET

import requests
from statemachine import StateMachine, State


def mac_status(net, mac):
    process = subprocess.Popen(['sudo', 'nmap', '-oX', '/tmp/nmap.xml', '-sn', net],
                               stdout=subprocess.PIPE)
    process.wait()

    tree = ET.parse('/tmp/nmap.xml')
    for node in tree.iter('address'):
        if node.attrib['addrtype'] == 'mac' and node.attrib['addr'] == mac:
            return 'present'
    return 'absent'


class MacAddressMonitoringMachine(StateMachine):
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

    args = parser.parse_args()

    sm = MacAddressMonitoringMachine()

    # Since we initialized the state machine to 'present' as the
    # initial state, we need to verify that.
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

        time.sleep(45)


if __name__ == '__main__':
    main()
