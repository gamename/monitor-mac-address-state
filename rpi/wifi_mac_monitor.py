import subprocess
import time
import xml.etree.ElementTree as ET

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

    def before_cycle(self, event: str, source: State, target: State, message: str = ""):
        message = ". " + message if message else ""
        return f"Running {event} from {source.id} to {target.id}{message}"


network_address = '192.168.0.1/24'
# mac_address = '28:CD:C1:04:80:97'
mac_address = '28:CD:C1:04:7F:69'

sm = MacAddressMonitoringMachine()

if mac_status(network_address, mac_address) != 'present':
    sm.send('cycle')

print(sm.current_state.id)

current = sm.current_state.id

while True:
    sample = mac_status(network_address, mac_address)
    if sample != current:
        print(f'{current}->{sample}')
        sm.send('cycle')
        current = sample
    time.sleep(45)
