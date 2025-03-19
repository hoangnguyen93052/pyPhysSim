import json
import socket
import threading
from time import sleep

class Packet:
    def __init__(self, src, dest, data):
        self.src = src
        self.dest = dest
        self.data = data

    def serialize(self):
        return json.dumps(self.__dict__)

    @staticmethod
    def deserialize(data):
        obj = json.loads(data)
        return Packet(obj['src'], obj['dest'], obj['data'])

class Switch:
    def __init__(self, switch_id):
        self.switch_id = switch_id
        self.ports = {}
        self.flows = {}

    def add_port(self, port_id):
        self.ports[port_id] = []

    def remove_port(self, port_id):
        if port_id in self.ports:
            del self.ports[port_id]

    def add_flow(self, packet, out_port):
        self.flows[packet.src] = out_port

    def process_packet(self, packet):
        out_port = self.flows.get(packet.src)
        if out_port:
            print(f"Switch {self.switch_id}: Forwarding packet from {packet.src} to {out_port}")
        else:
            print(f"Switch {self.switch_id}: No flow for packet from {packet.src}")

class Controller:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.switches = {}

    def add_switch(self, switch_id):
        self.switches[switch_id] = Switch(switch_id)

    def remove_switch(self, switch_id):
        if switch_id in self.switches:
            del self.switches[switch_id]

    def receive_packet(self, packet_json):
        packet = Packet.deserialize(packet_json)
        for switch in self.switches.values():
            switch.process_packet(packet)

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            print(f"Controller listening on {self.host}:{self.port}")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_client, args=(conn,)).start()

    def handle_client(self, conn):
        with conn:
            print('Connected by', conn.getpeername())
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                self.receive_packet(data.decode())

class Network:
    def __init__(self):
        self.controller = Controller('localhost', 5000)

    def add_switch(self, switch_id):
        self.controller.add_switch(switch_id)

    def start(self):
        threading.Thread(target=self.controller.start).start()

    def send_packet(self, packet):
        # Simulate sending a packet to the controller
        packet_json = packet.serialize()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.controller.host, self.controller.port))
            s.sendall(packet_json.encode())

def main():
    network = Network()
    network.start()

    sleep(1)  # Wait for the controller to start

    switch_id = 'switch1'
    network.add_switch(switch_id)
    
    switch = network.controller.switches[switch_id]
    switch.add_port('port1')
    switch.add_flow(Packet('A', 'B', 'Hello'), 'port1')

    packet = Packet('A', 'B', 'Hello')
    network.send_packet(packet)

    sleep(2)  # Allow some time to process packets

if __name__ == "__main__":
    main()