import socket as sk
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from node import Node
import argparse
import time

semaforo = 0
buffer = ''
def node_callback(event, node, connected_node, data, semaforo=0):
    try:
        if event != 'message received': # node_request_to_stop does not have any connected_node, while it is the main_node that is stopping!
            print('{}  {}\n'.format(event, data))
        elif (event == 'message received') and (semaforo == 1):
            #print('\n')
            #print('{}  {}\n'.format(event, data))
            buffer = event + data + '\n'
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

def menu():
    print('Digitare i seguenti comandi disponibili:\n')
    print("'connect username' per provare a contattare l'username desiderato\n ")
    print("'to username' per inviare un messaggio ad utente specifico\n")
    print("'end' per terminare\n")

if __name__ == '__main__':
    args = parse_args()
    node = Node(args.ip, args.port, node_callback)
    node.start()
    connected = {}
    msg = ''
    menu()
    while 1:

        msg = input('>>')
        choice = msg.split()
        if (choice[0] == 'connect') and (choice[1] is not []):
            # tentativo di connessione all'utente

            node.connect_with_node(args.destination_ip, args.destination_port)
            connected[choice[1]] = node.nodes_outbound[node.outbound_counter-1]
            continue
        if (choice[0] == 'to') and (choice[1] is not []):
            # devo inviare un messaggio al peer specificato
            # controllo che il peer sia connesso
            if choice[1] in connected:
                # invia il messaggio
                tstamp = time.strftime('%H:%M:%S', time.localtime())
                str = args.username + ': ' + msg + ' [' + tstamp + ']'
                node.send_to_node(connected[choice[1]], str)
            else:
                print("Specified user is not connected, please connect first to the user with 'connect' command\n")
                continue
        if choice[0] == 'end':
            # chiudere tutte le connessioni e terminare il client
            node.send_to_nodes(args.username + ' disconnected.')
            node.stop()
            exit(1)

            """if (msg == 'start') and (connected is False):
                node.connect_with_node(args.destination_ip, args.destination_port)
                node_reference = node.nodes_outbound[node.outbound_counter-1]
                connected = True
            if connected:
                tstamp = time.strftime('%H:%M:%S', time.localtime())
                str = args.username + ': ' + msg + ' [' + tstamp + ']'
                node.send_to_node(node_reference, str)
            if msg == 'contatta':
    
            if msg == 'end':
                node.outbound_node_disconnected(node_reference)
                print('sessione chiusa')
                exit(1)"""

