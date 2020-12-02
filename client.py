import binascii
import socket as sk
from base64 import b64decode

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
#from p2pnetwork.node import Node
from node import Node
import time
import argparse
from Crypto.Hash import HMAC, SHA256

buffer = ''

def parse_args():
    parser = argparse.ArgumentParser(description='p2p')
    group = parser.add_argument_group('Arguments')
    group.add_argument('-u', '--username', required=True, type=str, help="User nickname")
    group.add_argument('-bp', '--port', required=True, type=int, help='Port')
    group.add_argument('-bi', '--ip', required=True, type=str, help='IP Address')
    arguments = parser.parse_args()
    return arguments



def logout(username):    #TODO!
    prova = 1
    return prova

def login(username):
    esito = -1
    print("sono nella login")
    print(username)
    socket.sendall(bytes('2'+username, 'utf-8'))
    check = socket.recv(2048)
    check = check.decode('utf-8')
    print("CHECK: ", check)
    if check == '-1':  #in caso di utente non registrato il server risponde con codice -1
        print("Please")
        return esito

    messaggio = socket.recv(2048)
    print("Messaggio ricevuto:",messaggio)
    f = open(username + '.pem', 'r')      #recupero la mia chiave privata
    private_key = RSA.import_key(f.read())
    f.close()
    print("Chiave privata prelevata dal file:",private_key)

    cipher_rsa = PKCS1_OAEP.new(private_key)
    message = cipher_rsa.decrypt(messaggio)  #decifro il messaggio (random) ricevuto dal server con la mia chiave privata

    print("Messaggio decifrato",message)

    f = open('serverPubKey.pem', 'r')
    serverPub_key = RSA.import_key(f.read())            #recupero chiave pubblica del server
    cipher_rsa = PKCS1_OAEP.new(serverPub_key)
    message = cipher_rsa.encrypt(message)               #cifro con chiave pubblica del server e mando
    socket.sendall(message)
    print("Mandato message")

    receved = socket.recv(1024)    #se l'autenticazione è andata a buon fine il server me lo segnala
    receved = receved.decode('utf-8')
    print("Ricevuto capo:",receved)

    '''
    #PROVA PER CIFRATURA MESSAGGI CLIENT
    c_secret = socket.recv(2048)
    #decifro il segreto
    cipher_rsa = PKCS1_OAEP.new(private_key)
    secret = cipher_rsa.decrypt(c_secret)

    print("Ho ricevuto il segreto ed è:",secret)
    #cifro con chiave pubblica del server e glielo rimando
    cipher_rsa = PKCS1_OAEP.new(serverPub_key)
    c_secret = cipher_rsa.encrypt(secret)
    socket.sendall(c_secret)

    #ho ottenuto il segreto ora ricevo un messaggio di prova
    msg = socket.recv(2048)
    mac = socket.recv(2048)
    mac = mac.decode('utf-8')
    print("mac ricevuto è:",mac)
    h = HMAC.new(secret, msg ,digestmod=SHA256)
    try:
        h.hexverify(mac) #verifica che il mac è compatibile con msg
        msg = msg.decode('utf-8')
        print("Messaggio certificato:", msg)
    except:
        print("Messaggio non certificato")
    
    '''

    if receved == '1':                             #inviando 1 (da vedere se vogliamo cifrare anche questo), altrimenti
        print("LOGIN AVVENUTA CON SUCCESSO")        #qualsiasi cosa mi invia capisco che c'è stato un errore e ritorno errore(-1)
        return receved
    else:
        return esito


def connect_to_contact(contact, socket):
    try:
        '''Chiedo al server informazioni sull utente contact'''
        to_send = 'connect ' + contact
        socket.sendall(bytes(to_send, 'utf-8'))
        rcv = socket.recv(1024)
        received = rcv.decode("utf-8")
        if received != 'offline':
            return received  # restituisce la lista [ ip,porta]
        else:
            print('Utente ' + contact + 'offline.\n')
            return False
    except:
        print('Errore di comunicazione con-to-cont')


def node_callback(event, node, connected_node, data):
    try:
        if event != 'message received': # node_request_to_stop does not have any connected_node, while it is the main_node that is stopping!
            print('{}: {}'.format(event, data))
        elif event == 'message received':
            buffer = event + data + '\n'
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

    print("Ecco la stringa ricevuta: ", stringa)

    # decifro con chiave privata del client
    cipher_rsa = PKCS1_OAEP.new(keys)
    stringa_decifrata = cipher_rsa.decrypt(stringa)

    print("Stringa decifrata :", stringa_decifrata)

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


def menu_():
    print('Use the following commands to interact:\n')
    print("-'connect username' try to contact desired user.\n ")
    print("If no error occur, after this you can digit your messages and them will be sent\n"
          "through the last connection until a new 'connect username' occur.")
    print("-'end' close all the connection with this peer, end the program.\n")
    print("-'menu' review following commands. \n")

if __name__ == '__main__':
    args = parse_args()
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
            if comando == '1':
                signup(args.username)
                continue
            else:
                logged = login(args.username)
                if logged == '1':      #login avvenuta con successo
                    loggato = 1
                    menu = 1
                elif logged == '-1':
                    continue
        elif comando == 3:
            if loggato == 1:
                socket.sendall(bytes('3 '+args.username, 'utf-8'))
            socket.close()
            exit(1)
        else:
            print('Please, use one of the given command')
    '''
    while menu == 1:
        comando = input("1--> connect to another host\n"
                        "2--> logout\n"
                        "3--> quit\n"
                        ">>")
        if comando == 1:
            prova = 1        #da togliere
            #connect_to_contact()
        elif comando == 2:
            menu = 0
            logout(args.username)
        else:
            logout(args.username)
            socket.close()
            exit()
    '''
    node = Node(args.ip, args.port, node_callback)
    node.start()
    connected = {}      #dizionario dei peer connessi
    msg = ''
    receiver = ''
    menu_()
    while 1:
        #>> connect username mi connette all'utente username e i messaggi successivi vengono inviati a lui
        # finche' non viene eseguita una connect username2

        if buffer != '':
            print(buffer)
            buffer = ''
        msg = input(args.username + '>>' + receiver + ':')
        choice = msg.split()
        if (choice[0] == 'connect') and (choice[1] != []):
            if (connected == {}) or (choice[1] not in connected):
                # tentativo di connessione all'utente
                tupla = connect_to_contact(choice[1], socket)
                # !! POINT: possiamo garantire che i dati ricevuti siano corretti per quell' utente?
                # 1) trudy non ha manipolato i dati scambiandoli con quelli di qualcun altro
                if tupla != False:
                    print('Connected to ' + choice[1])
                    # mi connetto al nodo destinatario con i dati forniti dal server
                    node.connect_with_node(tupla[0], tupla[1])
                    # mantengo aggiornato un dizionario di referenze username:nodo
                    connected[choice[1]] = node.nodes_outbound[node.outbound_counter - 1]
                    receiver = choice[1]
                    continue
                continue

        #BUG: Che succede se un peer si disconnette?trascurabile per i nostri scopi
        elif receiver != '':
            # devo inviare un messaggio al peer specificato
            # controllo che il peer sia connesso
            if receiver in connected:
                # invia il messaggio
                tstamp = time.strftime('%H:%M:%S', time.localtime())
                str = args.username + ': ' + msg + ' [' + tstamp + ']'
                node.send_to_node(connected[choice[1]], str)
                continue
            else:
                print("Specified user is not connected, please connect first to the user with 'connect' command\n")
                continue
        elif choice[0] == 'end':
            # chiudere tutte le connessioni e terminare il client
            node.send_to_nodes(args.username + ' disconnected.')
            node.stop()

            exit(1)
        elif choice[0] == 'menu':
            menu_()
            continue
        else:
            print('Please, use one of te specified command')

