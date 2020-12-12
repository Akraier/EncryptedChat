import binascii
import socket as sk
from base64 import b64decode
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256 as s256

#from p2pnetwork.node import Node
from node import Node
import time
import argparse
import string
import random
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

def get_random_string(length):
    # Random string with the combination of lower and upper case
    letters = string.ascii_letters
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

def communication_decrypt_rsa(message, name):
    #funzione che decifra message secondo l'algoritmo RSA
    f = open(name + '.pem', 'r')  # recupero la mia chiave privata
    private_key = RSA.import_key(f.read())
    f.close()
    to_decrypt = message[:len(message)]
    cipher_rsa = PKCS1_OAEP.new(private_key)
    message_ = cipher_rsa.decrypt(to_decrypt)  # decifro il messaggio ricevuto dal peer con la mia chiave privata
    return message_.decode('utf-8')


def genera_mac(secret_, buff_mac):
    #print("Il segreto è:", secret_)
    h = HMAC.new(secret_, bytes(buff_mac,'utf-8'), digestmod=SHA256)
    mac = h.hexdigest()
    #print("Il mac generato è:", mac)
    return mac

def login(username):
    esito = -1
    socket.sendall(bytes('2'+username, 'utf-8'))
    check = socket.recv(1)
    check = check.decode('utf-8')
    if check == '-1':  #in caso di utente non registrato il server risponde con codice -1
        print("Please")
        return esito

    messaggio = socket.recv(2048)
    print("Recupero chiave privata...")
    print("Decifro con RSA la stringa di autenticazione ricevuta...")
    secret = communication_decrypt_rsa(messaggio, username)

    #print("Messaggio decifrato", secret)
    print("Recupero chiave pubblica server...")
    f = open('serverPubKey.pem', 'r')
    serverPub_key = RSA.import_key(f.read())            #recupero chiave pubblica del server
    cipher_rsa = PKCS1_OAEP.new(serverPub_key)
    print("Cifratura con RSA della stringa di conferma...")
    message = cipher_rsa.encrypt(bytes(secret,'utf-8'))               #cifro con chiave pubblica del server e mando
    socket.sendall(message)

    socket.sendall(bytes(str(args.port), 'utf-8'))
    secret_ok = socket.recv(1)

    if secret_ok.decode('utf-8') == '1':
        buffer_login = '2' + username + '1' + secret + '1'

        print("Genero MAC di conferma...")
        mac = genera_mac(bytes(secret,'utf-8'), buffer_login)

        print("Invio MAC al server")
        socket.sendall(bytes(mac, 'utf-8'))

        risposta = socket.recv(2048)

        print("Verifica MAC...")
        if mac == risposta.decode('utf8'):
            global segreto
            segreto = secret
            print("Login effettuato con successo")
            return 1
        else:
            print("Errore in fase di login, riprovare")
    else:
        print("Stringa segreta non ricevuta correttamente")
        return

def connect_to_contact(contact, socket):
    try:
        '''Chiedo al server informazioni sull utente contact'''
        to_send = 'connect ' + contact
        socket.sendall(bytes(to_send, 'utf-8'))
        rcv = socket.recv(1024)
        received = rcv.decode("utf-8")
        rec_split = received.split('///')

        #Generazione mac
        mac_buffer = rec_split[0] + ' ' + to_send
        mac_ = genera_mac(bytes(segreto,'utf-8') , mac_buffer)

        if (rec_split[0] != 'offline') and (mac_ == rec_split[1]):
            return received  # restituisce la lista [ ip,porta]
        else:
            print('Utente ' + contact + 'offline.\n')
            return '0'
    except:
        print('Errore di comunicazione con-to-cont')


def aes_decrypt(nonce, ciphertext, tag, key):
    cipher = AES.new(bytes(key, 'utf-8'), AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext
    except:
        print("AES error")
        return 0


def node_callback(event, node, connected_node, data):

    if (event == 'outbound_node_connected') :
        #sender generate this event when successfully connect to a node
        global id
        global id_user
        id = connected_node.id

    elif (event == 'message sent'):
        print("Messaggio cifrato inviato: ", data)

    elif event == 'message received ':
        init = ''
        try:
            init = data[0:5].decode('utf-8')
        except:
            print('NOPE')

        if init == 'init1':
            #prima fase dello scambio di chiavi
            plaintext = communication_decrypt_rsa(data[6:len(data)-1], args.username)
            sender_name, half_aes_key = plaintext.split()
            ret = connect_to_contact(sender_name, socket)
            if ret != 0:
                global receiver
                address = ret.split(" ")
                # mi connetto al nodo destinatario con i dati forniti dal server
                second_half = get_random_string(8)
                aes_key = half_aes_key + second_half
                node.connect_with_node(str(address[1]), int(address[2]))
                values = [node.nodes_outbound[node.outbound_counter - 1], ret.split("***")[1], aes_key, 1]
                node.connected.update({sender_name: values})
                #bob deve rispondere con la seconda parte della chiave

                to_send = args.username + ' ' + second_half
                key_crypt = RSA.import_key(node.connected[sender_name][1])
                chiper_rsa = PKCS1_OAEP.new(key_crypt)
                str_encrypted = chiper_rsa.encrypt(bytes(to_send, 'utf-8'))
                node.send_to_node(node.connected[sender_name][0], bytes("init2 ",'utf-8')+str_encrypted)
                receiver = sender_name
        elif init == 'init2':
            plaintext = communication_decrypt_rsa(data[6:len(data)-1], args.username)
            sender_name, sec_half = plaintext.split()
            if sender_name in node.connected: #altrimenti sec non e' giustificato
                node.connected[sender_name][2] += sec_half
                node.connected[sender_name][3] = 1
            else:
                print('utente non connesso')
        else:
            dict = eval(data[:len(data)-1].decode('utf-8'))
            print("Messaggio ricevuto: ", dict)

            username = dict['username']

            #qui posso decifrare con aes
            print("Sto decifrando il messaggio...")
            plaintext = aes_decrypt(dict['nonce'],dict['ciphertext'],dict['tag'], node.connected[username][2])

            this_mac = plaintext[0:64]
            messaggio = plaintext[64:len(plaintext)].decode('utf-8')

            # check mac
            secret = bytes(node.connected[username][2], 'utf-8')
            print("Calcolo e controllo MAC...")
            mac_rec = genera_mac(secret, messaggio)

            command = messaggio.split()[1]
            if command == 'disconnected.':
                if receiver == username:
                    receiver = ''
                    print(messaggio + " Connect to another user.")
                node.connected.pop(username)
                return

            if mac_rec != this_mac.decode('utf-8'):
                print("Il messaggio è stato manomesso")
                return

            print(username + '>>' + messaggio)



def signup(username):
    #avvio comunicazione con server
    socket.sendall(bytes('1' + username, 'utf-8'))

    print("Sto generando le mie chiavi...")
    keys = RSA.generate(2048)  # client genera la chiave privata
    private_key_PEM = keys.export_key()
    f = open(username + '.pem', 'wb')  # crea un file per salvarla
    f.write(private_key_PEM)
    f.close()

    public_key = keys.publickey() # generazione chiave pubblica
    public_key_send = public_key.export_key()

    # spedisco al server la chiave pubblica
    print("Invio chiave pubblica al server...")
    socket.sendall(public_key_send)
    # aspetto stringa casuale criptata
    stringa = socket.recv(2048)

    # decifro con chiave privata del client
    print("Decifro stringa di conferma ricevuta con la mia chiave privata...")
    stringa_decifrata = communication_decrypt_rsa(stringa, username)

    # invio la stringa decifrata al server
    buff_mac = '1' + username + public_key_send.decode('utf-8') + stringa_decifrata
    mac = genera_mac(bytes(stringa_decifrata,'utf-8'), buff_mac)
    print("Genero MAC di conferma...")

    socket.sendall(bytes(mac,'utf-8'))  # mando il MAC
    print("Invio MAC...")

    risposta = socket.recv(2048)
    print("Verifico MAC...")
    if risposta.decode('utf-8') == mac:
        print("Registrazione effettuata con successo")

    else:
        print("registraazione rifiutata")

def menu_():
    print('Use the following commands to interact:\n')
    print("-'connect username' try to contact desired user.\n ")
    print("If no error occur, after this you can digit your messages and them will be sent\n"
          "through the last connection until a new 'connect username' occur.")
    print("-'end' close all the connection with this peer, end the program.\n")
    print("-'menu' review following commands. \n")


def key_exchange(username, node_):

    first_half = get_random_string(8) #genero chiave
    node.connected[receiver][2] = first_half
    #first message
    x = username + ' ' + first_half
    #print(x)
    key_ = RSA.import_key(node.connected[receiver][1]) #prelevo chiave pubblica di bob
    cipher = PKCS1_OAEP.new(key_)

    encrypted = cipher.encrypt(bytes(x, 'utf-8')) #chiave cifrata con chiave pubblica di bob

    node_.send_to_node(node.connected[receiver][0], bytes('init1 ', 'utf-8') + encrypted)        #invio il messaggio cifrato

#dichiarazioni variabili globali
id = ''
id_user = dict()
receiver = ''
segreto = ''
if __name__ == '__main__':
    args = parse_args()
    host = sk.gethostname()
    port = 12345
    socket = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
    socket.connect((host, port))

    loggato = 0

    print("**************WELCOME TO ENCRYPTED CHAT****************\n")

    while 1:
        comando = input("1--> signup\n"
                        "2--> login\n"
                        "3--> quit\n"
                        ">>")

        if comando == '1' or comando == '2':
            if comando == '1':
                signup(args.username)
                continue
            else:
                loggato = login(args.username)
                #print(loggato)
                if loggato == 1:      #login avvenuta con successo
                    break
                elif loggato == -1:
                    continue
        elif comando == '3':
            if loggato == 1:
                socket.sendall(bytes('3 '+args.username, 'utf-8'))
            socket.close()
            exit(1)
        else:
            print('Please, use one of the given command')

    node = Node(args.ip, args.port, args.username, node_callback)
    node.start()
    #connected = {}      #dizionario dei peer connessi
    msg = ''

    menu_()
    while 1:
        #>> connect username mi connette all'utente username e i messaggi successivi vengono inviati a lui
        # finche' non viene eseguita una connect username2
        msg = input(args.username + '>>' + receiver + ':')
        choice = msg.split()
        if (choice[0] == 'connect') and (choice[1] != []):
            if (choice[1] not in node.connected) or (node.connected[choice[1]][3] == 0):
                # tentativo di connessione all'utente
                tupla = connect_to_contact(choice[1], socket)
                # !! POINT: possiamo garantire che i dati ricevuti siano corretti per quell' utente?
                # 1) trudy non ha manipolato i dati scambiandoli con quelli di qualcun altro
                if tupla != '0':
                    address = tupla.split(" ")
                    # mi connetto al nodo destinatario con i dati forniti dal server
                    node.connect_with_node(str(address[1]), int(address[2]))
                    id_user.update({id:choice[1]})
                    # mantengo aggiornato un dizionario di referenze username:[nodo,chiave pubblica, chiave aes]
                    values = [node.nodes_outbound[node.outbound_counter - 1], tupla.split("***")[1], "", 0]
                    node.connected.update({choice[1] : values})
                    receiver = choice[1]
                    key_exchange(args.username, node) #effettuo lo scambio di chiavi

                    continue
                continue
            if (node.connected[choice[1]][3] == 1) and ( choice[1] != receiver):
                tupla = connect_to_contact(choice[1], socket)
                if tupla != '0':
                    address = tupla.split(" ")
                    node.connect_with_node(str(address[1]), int(address[2]))
        elif choice[0] == 'end':
            # chiudere tutte le connessioni e terminare il client
            for n in node.connected:
                to_send = args.username+' disconnected.'
                cipher_aes = AES.new(bytes(node.connected[n][2], 'utf-8'),AES.MODE_EAX)  # valutare se trasformare in bytes
                print("Pare che la chiave simmetrica sia:", node.connected[receiver][2])
                nonce = cipher_aes.nonce
                # MAC
                mac = genera_mac(bytes(node.connected[n][2], 'utf-8'), to_send)
                print("Mac generato dal sender:", mac)
                str_tosend = mac + to_send
                ciphertext, tag = cipher_aes.encrypt_and_digest(bytes(str_tosend, 'utf-8'))

                aes = {'ciphertext': ciphertext,
                       'nonce': nonce,
                       'tag': tag,
                       'username': args.username}

                json_data = str(aes)
                node.send_to_node(node.connected[n][0], json_data)


            node.stop()
            socket.sendall(bytes('3' + args.username, 'utf-8'))
            socket.close()
            exit(1)
        elif choice[0] == 'menu':
            menu_()
            continue
        elif receiver != '':
            # devo inviare un messaggio al peer specificato
            # controllo che il peer sia connesso
            if receiver in node.connected:
                # invia il messaggio
                tstamp = time.strftime('%H:%M:%S', time.localtime())
                str_mess = ': ' + msg + ' [' + tstamp + ']'

                #CIFRATURA

                cipher_aes = AES.new(bytes(node.connected[receiver][2], 'utf-8'), AES.MODE_EAX) #valutare se trasformare in bytes
                nonce = cipher_aes.nonce
                #MAC
                print("Sto calcolando il MAC...")
                mac = genera_mac(bytes(node.connected[receiver][2], 'utf-8'), str_mess)

                str_tosend = mac + str_mess

                print("Sto cifrando con AES...")
                ciphertext, tag = cipher_aes.encrypt_and_digest(bytes(str_tosend, 'utf-8'))

                aes = {'ciphertext':ciphertext,
                       'nonce':nonce,
                       'tag':tag,
                       'username':args.username}

                json_data = str(aes)
                node.send_to_node(node.connected[receiver][0], json_data )
                continue
            else:
                print("Specified user is not connected, please connect first to the user with 'connect' command\n")
                continue

        else:
            print('Please, use one of te specified command')

