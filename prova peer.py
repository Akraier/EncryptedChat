from pyp2p.net import *
from pyp2p.unl import UNL
from pyp2p.dht_msg import DHT
import time
alice_dht = DHT()
alice_direct = Net(passive_bind="192.168.0.45", passive_port=44444, interface='eth0:2', net_type='direct', dht_node=alice_dht, debug=1)
alice_direct.start()

bob_dht = DHT()
bob_direct = Net(passive_bind="192.168.0.44", passive_port=44444, interface='eth0:1', net_type='direct', dht_node=alice_dht, debug=1)
bob_direct.start()

def success(con):
    print("Alice successfully connected to Bob.")
    con.send_line("Sup Bob.")

def failure(con):
    print("Alice failed to connect to Bob")

events = {
    "success" : success,
    "failure" : failure
}

alice_direct.unl.connect(bob_direct.unl.construct(),events)

while 1:
    for con in bob_direct:
        for reply in con:
            print(reply)

    for con in alice_direct:
        x=1
time.sleep(0.5)