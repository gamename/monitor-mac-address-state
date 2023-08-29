import subprocess
import xml.etree.ElementTree as ET
from statemachine import StateMachine, State


class MacAddressMonitoringMachine(StateMachine):
    present = State()
    absent = State()
    cycle = (present.to(absent) | absent.to(present))

    def before_cycle(self, event: str, source: State, target: State, message: str = ""):
        message = ". " + message if message else ""
        return f"Running {event} from {source.id} to {target.id}{message}"


network_address = '192.168.0.1/24'
mac_address = '28:CD:C1:04:80:97'

process = subprocess.Popen(['sudo', 'nmap', '-oX', '/tmp/nmap.xml', '-sn', network_address],
                           stdout=subprocess.PIPE)
process.wait()

tree = ET.parse('/tmp/nmap.xml')
for node in tree.iter('address'):
    if node.attrib['addrtype'] == 'mac' and node.attrib['addr'] == mac_address:
        print(node.attrib['addr'])
