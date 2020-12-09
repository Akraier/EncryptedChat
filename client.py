import binascii
import socket as sk
from base64 import b64decode

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

def genera_mac(secret_, buff_mac):
    print("Il segreto è:", secret_)
    h = HMAC.new(secret_, bytes(buff_mac,'utf-8'), digestmod=SHA256)
    mac = h.hexdigest()
    print("Il mac generato è:", mac)

    return mac

def login(username):
    esito = -1
    print("sono nella login")
    print(username)
    socket.sendall(bytes('2'+username, 'utf-8'))
    check = socket.recv(1)
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
    print("Chiave privata prelevata dal file:", private_key)

    cipher_rsa = PKCS1_OAEP.new(private_key)

    secret = cipher_rsa.decrypt(messaggio)  #decifro il messaggio (random) ricevuto dal server con la mia chiave privata

    print("Messaggio decifrato", secret)

    f = open('serverPubKey.pem', 'r')
    serverPub_key = RSA.import_key(f.read())            #recupero chiave pubblica del server
    cipher_rsa = PKCS1_OAEP.new(serverPub_key)
    message = cipher_rsa.encrypt(secret)               #cifro con chiave pubblica del server e mando
    socket.sendall(message)
    print("Mandato message:", message)

    socket.sendall(bytes(str(args.port), 'utf-8'))
    print("Ho Inviato la porta:", args.port)
    print("La porta aveva dimensione:", len(bytes(str(args.port), 'utf-8')))
    print("pre riempimento")
    secret_ok = socket.recv(1)
    print("Check segreto:",secret_ok)
    if secret_ok.decode('utf-8') == '1':
        buffer_login = '2' + username + '1' + secret.decode('utf-8') + '1'
        print("buffer_login riempito:", buffer_login)
        mac = genera_mac(secret, buffer_login)
        print("mac generato: ", mac)
        print(len(bytes(mac, 'utf-8')))
        socket.sendall(bytes(mac, 'utf-8'))
        print("mac inviato")
        risposta = socket.recv(2048)
        print("risposta ricevuta")
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
        print('ricevuto ', received)
        rec_split = received.split('///')
        #rec_split[0] messaggio rec_split[1] mac
        mac_buffer = rec_split[0] + ' ' + to_send
        print(mac_buffer)
        mac_ = genera_mac(segreto, mac_buffer)
        print('mac ', mac_)
        if (rec_split[0] != 'offline') and (mac_ == rec_split[1]):
            return received  # restituisce la lista [ ip,porta]
        else:
            print('Utente ' + contact + 'offline.\n')
            return '0'
    except:
        print('Errore di comunicazione con-to-cont')

def comunication_decrypt_rsa(message, name):
    #funzione che decifra message ricevuto da name
    f = open(name + '.pem', 'r')  # recupero la mia chiave privata
    private_key = RSA.import_key(f.read())
    f.close()
    to_decrypt = message[:len(message) - 1]
    cipher_rsa = PKCS1_OAEP.new(private_key)
    message_ = cipher_rsa.decrypt(to_decrypt)  # decifro il messaggioricevuto dal peer con la mia chiave privata
    return message_.decode('utf-8')
def aes_decrypt(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce = nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        print("Aes ok")
        return plaintext
    except:
        print("AES error")
        return 0
def node_callback(event, node, connected_node, data):
    if event != 'message received ':  # node_request_to_stop does not have any connected_node, while it is the main_node that is stopping!
        print('{}: {}'.format(event, data))
    elif event == 'message received ':
        #node ricevente, connected_node mittente

        if (connected_node.username in node.connected) and (node.connected[connected_node.username][4] == 0):
            #receiver already connected to sender
            #aes key available, can decrypt aes message
            nonce, ciphertext, tag = data.split()
            ret = aes_decrypt(nonce, ciphertext, tag,node.connected[connected_node][2])
            if ret != 0:
                print(ret)

        elif (connected_node.username not in node.connected):
            #receiver not connected, waiting for first message
            #user aes_key
            rsa_decrypted = comunication_decrypt_rsa(data, node.username)
            rsa_decrypted_splitted = rsa_decrypted.split() #[0] user [1]aes_key
            if rsa_decrypted_splitted[0] == connected_node.username:
                #verify sender node(hackable?lib vulnerability)
                ret = connect_to_contact(rsa_decrypted_splitted[0], socket) #asking server sender info
                #build mac for this data. Verify in the next step
                h = HMAC.new(bytes(rsa_decrypted_splitted[1]), digestmod=SHA256)
                h.update(bytes(rsa_decrypted))
                k = h.hexdigest()
                values = [connected_node, ret.split("***")[1], rsa_decrypted_splitted[1], k, 1]
                node.connected.update({connected_node.username:values}) #building the entry, deleted if mac or sign non verified
        elif (connected_node.username in node.connected) and (node.connected[connected_node.username][4]==1):
            #mac AES(sign)=(nonce, cipherthext, tag)
            # verify mac
            mac, aes = data.split()
            try:
                node.connected[connected_node.username][3].hexverify(mac)
                print('mac OK')
            except:
                print('mac NOT OK')
                #to delete user in connected and return
                node.connected.pop(connected_node.username)
            #verify signature
            nonce, ciphertext, tag = aes.split('*')
            ret = aes_decrypt(nonce,ciphertext, tag, node.connected[connected_node.username][3])
            if ret != 0:
                #aes gone well
                #verify sign in ret
                key = RSA.import_key(node.connected[connected_node.username][2])
                h = SHA256.new(ret)
                try:
                    pkcs1_15.new(key).verify(h,ret)
                    print("signature gone well")
                    node.connected[connected_node.username][4]=0
                except:
                    print("signature gone wrong")
                    node.connected.pop(connected_node.username)
'''def node_callback(event, node, connected_node, data):
    global connected
    global receiver
    try:
        global receiver
        if str(event) != 'message received ': # node_request_to_stop does not have any connected_node, while it is the main_node that is stopping!
            print('{}: {}'.format(event, data))
        elif str(event) == 'message received ':
            try:
                type = data.decode('utf-8')
            except:
                print('fammi vede che succede')

            type_start = type.split('###')
            if type_start[0] == 'start1' :
                #messaggio di inizializzazione "key user realkey" contenuto in type_start[1]
                decrypted_1 = comunication_decrypt_rsa(type_start[1],args.username)
                kur = decrypted_1.split()
                ret = connect_to_contact(kur[2], socket) #richiedo al server i dati di bob
                if ret == '0':
                    print('errore durante lo scambio di chiave')
                    exit()
                else:
                    # inizializzo connected [nodo, pubK,AesK,mac] 
                    #genero il mac per type_start[1] con AesK e lo salvo in connected
                    h = HMAC.new(bytes(kur[2], 'utf-8'), digestmod=SHA256)
                    h.update(type_start[1])
                    mac = h.hexdigest()
                    values = [node.nodes_outbound[node.outbound_counter - 1], ret.split("***")[1], kur[2], mac]
                    connected.update({kur[1]: values})  # aggiorno la variabile connected
            elif type_start[0] == 'start2':
                #start2###user??MAC AES
                
                user_coded = type_start[1].split('??')
                if (user_coded[0] in connected) and (connected[user_coded[0]][3]!=''):
                    #user ha effettuato start1 ed e' in attesa di start2
                    mac, aes_encrypted = user_coded[1].split('//') 
                    #decodifico mac e mi accerto che corrisponda
                    try:
                        
                    
            else:
                #decifro con aes
                to_print = comunication_decrypt(data,args.username)
                print(to_print)


            msg_splitted = msg.split('?###0001###?') # provo a splittare il messaggio ricevuto: [0] key_user [1] aes_key
            if len(msg_splitted) > 1:  # spero che nessun utente provi ad inviare '###' durante un mesasggio normale
                print("eccoci qua")
                key_user = msg_splitted[0].split() # [0] 'key'  [1] username
                #key_user_ = key_user[0].split() # [0] key [1] user
                if (key_user[0] == 'key') and (len(key_user) > 1): #controllo obsoleto forse
                    ret = connect_to_contact(key_user[1], socket) # chiedo al server le informazioni di bob
                    if ret == '0':
                        print('error during key exchange.')
                        exit()
                    else:
                        # devo prelevare la chiave pubblica di rx e provare a decifrare la firma
                        # e' il caso che provo ad inizializzare anche connected
                        print('eccoci qua2')
                        rx_pk = RSA.import_key(ret.split('***')[1])# chiave pubblica di bob
                        h = s256.new(bytes(msg, 'utf-8')) #genero hash del messaggio

                        try:
                            pkcs1_15.new(rx_pk).verify(h, bytes(msg_splitted[1]))
                            print("firma valida")
                        except:
                            #se fallisce la decrypt l'autenticita' non e' garantita
                            print('errore firma digitale')
                            return
                        # a questo punto posso salvare la chiave e stabilire la connessione
                        key_time = msg_splitted[1].split()
                        #controllo un record&playback
                        ts = time.time()
                        if int(key_time[1]) < ts-1:
                            print("Record&playback")
                            return
                        else:
                            values = [node.nodes_outbound[node.outbound_counter - 1], ret.split("***")[1], key_time[0]]
                            connected.update({key_user[1] : values}) #aggiorno la variabile connected
                            address = ret.split()
                            node.connect_with_node(str(address[1]), int(address[2]))
                            print("connected with " + key_user_[1])
                            receiver = key_user_[1]
            else:
                print('non il primo')

            splitted = msg.split()
            if (splitted[1] == 'disconnected.') and (splitted[0] in connected):
                connected.pop(splitted[0])
                receiver = ''
            print(args.username + '>>' + receiver + ':')
    except Exception as e:
        print(e)'''


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

    print("Stringa segreta decifrata :", stringa_decifrata)

    # invio la stringa decifrata al server
    #socket.sendall(stringa_decifrata)

    buff_mac = '1' + username + public_key_send.decode('utf-8') + stringa_decifrata.decode('utf-8')
    mac = genera_mac(stringa_decifrata,buff_mac)

    socket.sendall(bytes(mac,'utf-8'))  # mando il MAC

    risposta = socket.recv(2048)

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

def get_random_string(length):
    # Random string with the combination of lower and upper case
    letters = string.ascii_letters
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str


def key_exchange(username, node_):


    comunication_secret = get_random_string(16) #genero chiave
    node.connected[receiver][2] = comunication_secret
    #first message
    x = username + ' ' + comunication_secret
    print(x)
    key_ = RSA.import_key(node.connected[receiver][1]) #prelevo chiave pubblica di bob
    cipher = PKCS1_OAEP.new(key_)

    encrypted = cipher.encrypt(bytes(x, 'utf-8')) #chiave cifrata con chiave pubblica di bob
    print('cifrato ', encrypted)

    node_.send_to_node(node.connected[receiver][0], encrypted)        #invio il messaggio cifrato

    #firmo x
    digest = s256.new(bytes(x, 'utf-8'))
    # devo firmare con la chiave privata di alice
    filename = username +'.pem'
    with open(filename, 'r') as key_file:
        private = RSA.import_key(key_file.read())
    signature = pkcs1_15.new(private).sign(digest)

    #Genero un MAC
    h = HMAC.new(bytes(comunication_secret,'utf-8'), digestmod=SHA256)
    h.update(x)
    mac = h.hexdigest()
    #Cifro la firma con AES
    aes_cipher = AES.new(comunication_secret, AES.MODE_EAX)
    nonce = aes_cipher.nonce
    ciphertext, tag = aes_cipher.encrypt_and_digest(signature)

    #invio tutto al ricevente
    to_send = mac +' '+ str(nonce)+'*'+str(ciphertext)+'*'+str(tag)
    node_.send_to_node(node.connected[receiver][0], bytes(to_send,'utf-8'))  # invio la chiave cifrata


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
                print(loggato)
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
            if (node.connected == {}) or (choice[1] not in node.connected):
                # tentativo di connessione all'utente
                tupla = connect_to_contact(choice[1], socket)
                # !! POINT: possiamo garantire che i dati ricevuti siano corretti per quell' utente?
                # 1) trudy non ha manipolato i dati scambiandoli con quelli di qualcun altro
                if tupla != '0':
                    address = tupla.split(" ")
                    # mi connetto al nodo destinatario con i dati forniti dal server
                    node.connect_with_node(str(address[1]), int(address[2]))
                    # mantengo aggiornato un dizionario di referenze username:[nodo,chiave pubblica, chiave aes]
                    values = [node.nodes_outbound[node.outbound_counter - 1], tupla.split("***")[1], ""]
                    node.connected.update({choice[1] : values})
                    receiver = choice[1]
                    key_exchange(args.username, node) #effettuo lo scambio di chiavi

                    continue
                continue
        elif choice[0] == 'end':
            # chiudere tutte le connessioni e terminare il client
            for n in node.connected:
                print(n)
                key = RSA.import_key(node.connected[n][1])
                chiper = PKCS1_OAEP.new(key)
                encrypted = chiper.encrypt(bytes(args.username+' disconnected.', 'utf-8'))
                node.send_to_node(node.connected[n][0], encrypted)
            node.stop()
            socket.sendall(bytes('3' + args.username, 'utf-8'))
            socket.close()
            exit(1)
        elif choice[0] == 'menu':
            menu_()
            continue
        #BUG: Che succede se un peer si disconnette?trascurabile per i nostri scopi
        elif receiver != '':
            # devo inviare un messaggio al peer specificato
            # controllo che il peer sia connesso
            if receiver in node.connected:
                # invia il messaggio
                tstamp = time.strftime('%H:%M:%S', time.localtime())
                str_tosend = str(args.username) + ': ' + msg + ' [' + tstamp + ']'

                #CIFRATURA
                key_crypt = RSA.import_key(node.connected[receiver][1])
                chiper_rsa = PKCS1_OAEP.new(key_crypt) #valutare se trasformare in bytes
                str_encrypted = chiper_rsa.encrypt(bytes(str_tosend, 'utf-8'))
                print("len:", len(str_encrypted))
                node.send_to_node(node.connected[receiver][0], str_encrypted)
                continue
            else:
                print("Specified user is not connected, please connect first to the user with 'connect' command\n")
                continue

        else:
            print('Please, use one of te specified command')

