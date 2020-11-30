import socket as sk
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from node import Node
import argparse
import time


def node_callback(event, data):
    try:
        if event != 'node_request_to_stop': # node_request_to_stop does not have any connected_node, while it is the main_node that is stopping!
            print('Event {} : {}\n'.format(event, data))

    except Exception as e:
        print(e)


def parse_args():
    parser = argparse.ArgumentParser(description='p2p')
    group = parser.add_argument_group('Arguments')
    group.add_argument('-u', '--username', required=True, type=str, help="Username dell'utente")
    group.add_argument('-bp', '--port', required=True, type=int, help='Porta alla quale associare il peer')
    group.add_argument('-bi', '--ip', required=True, type=str, help= 'Indirizzo IP')
    group.add_argument('-dp', '--destination_port', required=True, type=int, help='Porta di destinazione')
    group.add_argument('-di', '--destination_ip', required=True, type=str, help='Ip di destinazione')
    arguments = parser.parse_args()
    return arguments


if __name__ == '__main__':
    args = parse_args()
    node = Node(args.ip, args.port, node_callback)
    node.start()
    msg = ''
    while 1:
        msg = input('>>')
        if msg == 'start':

            node.connect_with_node(args.destination_ip, args.destination_port)
            node_reference = node.nodes_outbound[node.outbound_counter-1]
            while 1:
                msg = input('>>')
                tstamp = time.strftime('%H:%M:%S', time.localtime())
                if msg == 'end':
                    node.outbound_node_disconnected(node_reference)
                    print('sessione chiusa')
                    exit(1)
                str = args.username + ':' + msg + ' [' + tstamp + ']'
                node.send_to_node(node_reference, str)
