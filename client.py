import binascii
import socket as sk
from base64 import b64decode

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from p2pnetwork.node import Node
import time

def logout(username):    #TODO!
    prova = 1
    return prova

def login(username):
    esito = -1
    print("sono nella login")
    socket.sendall(bytes('2'+username, 'utf-8'))
    check = socket.recv(1024)
    if check.decode('utf-8') == '-1':  #in caso di utente non registrato il server risponde con codice -1
        print("USERNAME NON REGISTRATO.")
        return esito

    f = open(username + '.pem', 'r')      #recupero la mia chiave privata
    private_key = RSA.import_key(f.read())
    f.close()

    cipher_rsa = PKCS1_OAEP.new(private_key)
    message = cipher_rsa.decrypt(ricevuto)  #decifro il messaggio (random) ricevuto dal server con la mia chiave privata

    f = open('serverPubKey.pem', 'r')
    serverPub_key = RSA.import_key(f.read())            #recupero chiave pubblica del server
    cipher_rsa = PKCS1_OAEP.new(serverPub_key)
    message = cipher_rsa.encrypt(message)               #cifro con chiave pubblica del server e mando
    socket.sendall(message)

    receved = socket.recv(1024)    #se l'autenticazione è andata a buon fine il server me lo segnala
    receved = receved.decode('utf-8')
    if receved == '1':                             #inviando 1 (da vedere se vogliamo cifrare anche questo), altrimenti
        print("LOGIN AVVENUTA CON SUCCESSO")        #qualsiasi cosa mi invia capisco che c'è stato un errore e ritorno errore(-1)
        return receved
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

    keys = RSA.generate(2048)  # client genera la chiave privata
    private_key_PEM = keys.export_key()
    f = open(username + '.pem', 'wb')  # crea un file per salvarla
    f.write(private_key_PEM)
    f.close()

    public_key = keys.publickey() # generazione chiave pubblica
    public_key_send = public_key.export_key()
    #public_key_send = public_key_send.decode('utf-8')

    # salvataggio chiave pubblica lato client ?

    #PROVE, ESEMPIO FUNZIONANTE DI CRIPTAZIONE E DECIFRAZIONE
   # mex = 'Ciao prova'
   # mex=bytes(mex,'utf-8')
   # encryptor = PKCS1_OAEP.new(public_key)  # PROVA
   # mex_cifrato = encryptor.encrypt(mex)  # PROVA
   # print("Messaggio cifrato: ",mex_cifrato)

   # decryptor = PKCS1_OAEP.new(keys)
   # mex_decifrato = decryptor.decrypt(mex_cifrato)
   # print("Ora l'ho decifrato: ",mex_decifrato)


    # spedisco al server la chiave pubblica
    #socket.sendall(bytes(public_key_send, 'utf-8')) #GIUSTO
    socket.sendall(public_key_send)
    print("Spedita la chiave: ",public_key_send)

    # aspetto stringa casuale criptata
    stringa = socket.recv(2048)

    print("Ecco la stringa ricevuta: ",stringa)

    # decifro con chiave privata del client
    cipher_rsa = PKCS1_OAEP.new(keys)
    stringa_decifrata = cipher_rsa.decrypt(stringa)

    print("Stringa decifrata :",stringa_decifrata)

    # invio la stringa cifrata al server
    socket.sendall(stringa_decifrata)

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

    host = sk.gethostname()
    port = 12345
    socket = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
    socket.connect((host, port))

    menu = 0
    print("**************WELCOME TO ENCRYPTED CHAT****************\n")

    while menu == 0:
        comando = input("1--> signup\n"
                        "2--> login\n"
                        "3--> quit\n"
                        ">>")

        if comando == '1' or comando == '2':
            username = input("inserisci il tuo username: ")
            if comando == '1':
                signup(username)
            else:
                if login(username) == '1':      #login avvenuta con successo
                    menu = 1
        else:
            socket.close()
            exit()

    while menu == 1:
        comando = input("1--> connect to another host\n"
                        "2--> logout\n"
                        "3--> quit\n"
                        ">>")
        if comando == 1:
            prova =1        #da togliere
            #connect_to_contact()
        elif comando == 2:
            menu = 0
            logout(username)
        else:
            logout(username)
            socket.close()
            exit()



    socket.sendall(bytes('Ciao bella!', 'utf-8'))
    ricevuto = socket.recv(1024)
    print(ricevuto)
    #socket.close()      #da togliere, farei una funzione logout per eliminare l'indirizzo ip
                        #dal server prima di chiudere
    signup(username)
    '''
    if login(username) == 1:
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

