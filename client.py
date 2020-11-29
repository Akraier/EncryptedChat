import socket as sk
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from p2pnetwork.node import Node
import time
def login(username):
    esito = -1
    print("sono nella login")
    socket.sendall(bytes('2'+username, 'utf-8'))
    ricevuto = socket.recv(1024)
    print('RICEVUTO: ', ricevuto)
    if ricevuto == '-1':            #in caso di utente non registrato il server risponde con codice -1?
        return esito

    f = open(username+'.pem', 'r')      #recupero la mia chiave privata
    private_key = RSA.import_key(f.read())
    f.close()

    cipher_rsa = PKCS1_OAEP.new(private_key)
    message = cipher_rsa.decrypt(ricevuto)  #decifro il messaggio (random) ricevuto dal server con la mia chiave privata

    f = open('serverPubKey.pem', 'r')
    serverPub_key = RSA.import_key(f.read())            #recupero chiave pubblica del server
    cipher_rsa = PKCS1_OAEP.new(serverPub_key)
    message = cipher_rsa.encrypt(message)               #cifro con chiave pubblica del server e mando
    socket.sendall(bytes(message, 'utf-8'))

    ricevuto = socket.recv(1024)             #se l'autenticazione è andata a buon fine il server me lo segnala
    if ricevuto == '1':                      #inviando 1 (da vedere se vogliamo cifrare anche questo), altrimenti
        return ricevuto                      #qualsiasi cosa mi invia capisco che c'è stato un errore e ritorno errore(-1)
    else:
        return esito

def connect_to_contact(contact, socket):
    try:
        to_send = 'connect' + contact
        socket.sendall(bytes(to_send, 'utf-8'))
        rcv = socket.recv(1024)
        received = rcv.decode("utf-8")


    except:
        print('Errore di comunicazione con-to-cont')
    if received != 'offline':
        return received   #restituisce la lista [ ip,porta]
    else:
        print('Utente ' + contact + 'offline.\n')
        return 0


def node_callback(event, node, connected_node, data):
    try:
        if event != 'node_request_to_stop': # node_request_to_stop does not have any connected_node, while it is the main_node that is stopping!
            print('Event: {} from main node {}: connected node {}: {}'.format(event, node.id, connected_node.id, data))

    except Exception as e:
        print(e)

def signup(username):
    print('SONO NELLA SIGNUP')
    #avvio comunicazione con server
    socket.sendall(bytes('1' + username, 'utf-8'))

    key = RSA.generate(2048)  # client genera la chiave privata
    private_key = key.export_key()
    f = open(username + '.pem', 'wb')  # crea un file per salvarla
    f.write(private_key)
    f.close()


    public_key = key.publickey().export_key() # generazione chiave pubblica
    # salvataggio chiave pubblica lato client ?

    public_key = public_key.decode('utf-8')
    # spedisco al server la mia chiave pubblica
        #socket.send(public_key.encode())
    socket.sendall(bytes(public_key, 'utf-8'))
    #public_key = public_key.decode('utf-8')
    print("Spedita la chiave: "+public_key)
    #socket.send(public_key.exportKey(format='PEM', passphrase=None, pkcs=1))

    # aspetto stringa generata casualmente
    stringa = socket.recv(16)
    stringa = stringa.decode('utf-8')


    print("Ecco la stringa ricevuta: "+stringa)
    # decifro con chiave privata del client
    cipher_rsa = PKCS1_OAEP.new(private_key)
    stringa_decifrata = stringa#stringa_decifrata = cipher_rsa.decrypt(stringa)


    # invio la stringa cifrata al server
    socket.sendall(bytes(stringa_decifrata, 'utf-8'))

    # aspetto l'ok
    esito = socket.recv(1024)
    esito = esito.decode('utf-8')
    print("L'esito è: "+esito)

    if esito == '0':
        print("Registrazione avvenuta con successo")
        return
    else:
        print("Si è verificato un errore")

if __name__ == '__main__':

    username = input("inserisci il tuo username: ")

    host = sk.gethostname()
    port = 12345
    socket = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
    socket.connect((host, port))
    socket.sendall(bytes('Ciao bella!', 'utf-8'))
    ricevuto = socket.recv(1024)
    print(ricevuto)
    #socket.close()      #da togliere, farei una funzione logout per eliminare l'indirizzo ip
                        #dal server prima di chiudere
    signup(username)
    '''if login(username) == 1:
        node = Node('127.0.0.1', 10001, node_callback)
        node.start()
        # devo chiedere al client chi vuole contattare
        contact = input("Username da contattare: ")
        addr_to_connect = connect_to_contact(contact, socket)
        if addr_to_connect != 0:  # e' possibile contattare l'utente richiesto
            addr_to_connect.split(" ")
            ip_to_connect = addr_to_connect[0]
            port_to_connect = addr_to_connect[1]
            node.connect_with_node(ip_to_connect, port_to_connect)
            # forse bisogna modificare la libreria affinche' sia disponibile
            # il nodo dall'altro lato
            print("Digita '!!' per chiudere la connessione\n")
            # trova un modo per contattare un altro utente
            msg = []
            while 1:
                msg = input('>>')
                if msg == '!!':
                    # chiudere la connessione
                    break
                else:
                    node.send_to_node()
    '''

''' def conn_to_server():
   try:
        socket = sk.socket(sk.AF_INET, sk.SOCK_STREAM) #creazione socket client
        socket.connect((indirizzo_server,porta_server)) #connessione al server
        print("Connessione al server effettuata")

        #creazione username e generazione key public e key private
        username = input("Inserire username:")
        socket.send(username, 'utf-8')


   except sk.error as errore:
        print("Connessione non riuscita"+errore)
'''

