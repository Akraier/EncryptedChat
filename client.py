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
    print(to_decrypt)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    message_ = cipher_rsa.decrypt(to_decrypt)  # decifro il messaggioricevuto dal peer con la mia chiave privata
    return message_.decode('utf-8')
def aes_decrypt(nonce, ciphertext, tag, key):
    cipher = AES.new(bytes(key,'utf-8'), AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        print("Aes ok")
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

        print('ID connesso', id)
    elif (event == 'inbound_node_connected'):
        print('NODE ',node)
        print('connected ',connected_node)
    elif event == 'message received ':
        print('NODE ', node)
        print('COnnected ', connected_node)
        #node ricevente, connected_node mittente
        #connected_node.id is the only
        #receiver_username = id_user[connected_node.id]
        print('DATA ', data)
        init = ''
        try:
            init = data[0:5].decode('utf-8')
            print('INIT ',init)
        except:
            print('NOPE')
        #init, rsa_cipher = received.split()

        if init == 'init1':
            #prima fase dello scambio di chiavi
            print('banana ',data[6:len(data)])
            plaintext = comunication_decrypt_rsa(data[6:len(data)], args.username)
            sender_name, half_aes_key = plaintext.split()
            ret = connect_to_contact(sender_name,socket)
            if ret != 0:
                global receiver
                address = ret.split(" ")
                # mi connetto al nodo destinatario con i dati forniti dal server
                second_half = get_random_string(8)
                aes_key = half_aes_key + second_half
                node.connect_with_node(str(address[1]), int(address[2]))
                values = [node.nodes_outbound[node.outbound_counter - 1], ret.split("***")[1],aes_key,1]
                node.connected.update({sender_name: values})
                #bob deve rispondere con la seconda parte della chiave

                to_send = args.username + ' ' + second_half
                key_crypt = RSA.import_key(node.connected[sender_name][1])
                chiper_rsa = PKCS1_OAEP.new(key_crypt)
                str_encrypted = chiper_rsa.encrypt(bytes(to_send, 'utf-8'))
                node.send_to_node(node.connected[sender_name][0], bytes("init2 ",'utf-8')+str_encrypted)
                receiver = sender_name
        elif init == 'init2':
            plaintext = comunication_decrypt_rsa(data[6:len(data)], args.username)
            sender_name, sec_half = plaintext.split()
            if sender_name in node.connected: #altrimenti sec non e' giustificato
                node.connected[sender_name][2] += sec_half
                node.connected[sender_name][3] = 1
            else:
                print('utente non connesso')
        else:
            print('bananan2 ', type(data))
            dict = eval(data[:len(data)-1].decode('utf-8'))
            print(dict)
            #dict_dec = dict.decode('utf-8')

            #dict = json.dumps(data)
            username = dict['username']
            print(username)
            '''userLen = data[0:2].decode('utf-8')
            print('LEN ',userLen)
            sender_name = data[3:int(userLen)].decode('utf-8')
            #sender_name, cipher = data.split()
            aes = data[int(userLen)+1:len(data)].decode('utf-8')
            nonce, ciphertext, tag = aes.split('*')'''
            #qui posso decifrare con aes

            plaintext  = aes_decrypt(dict['nonce'],dict['ciphertext'],dict['tag'], node.connected[username][2])
            '''if plaintext != 0:
                #la traduzione ha funzionato
                code, firma = plaintext.split('*')
                if code == 'firma':
                    #devo verificare la firma di alice
                    
                else:
                    print(sender_name + '>>' + plaintext)
            else:
                print('Aes decrypt failed')'''
            print(username + '>>' + plaintext.decode('utf-8'))
        '''if (receiver_username in node.connected) and (node.connected[receiver_username][4] == 0):
            #receiver already connected to sender
            #aes key available, can decrypt aes message
            nonce, ciphertext, tag = data.split()
            ret = aes_decrypt(nonce, ciphertext, tag,node.connected[connected_node][2])
            if ret != 0:
                print(ret)

        elif receiver_username not in node.connected:
            # receiver not connected, waiting for first message
            # user aes_key
            rsa_decrypted = comunication_decrypt_rsa(data, node.username)
            rsa_decrypted_splitted = rsa_decrypted.split() # [0] user [1]aes_key
            if rsa_decrypted_splitted[0] == receiver_username:
                # verify sender node(hackable?lib vulnerability)
                ret = connect_to_contact(rsa_decrypted_splitted[0], socket) #asking server sender info
                # build mac for this data. Verify in the next step
                h = HMAC.new(bytes(rsa_decrypted_splitted[1]), digestmod=SHA256)
                h.update(bytes(rsa_decrypted))
                k = h.hexdigest()
                values = [connected_node, ret.split("***")[1], rsa_decrypted_splitted[1], k, 1]
                node.connected.update({receiver_username:values}) # building the entry, deleted if mac or sign non verified
        elif (receiver_username in node.connected) and (node.connected[receiver_username][4]==1):
            # mac AES(sign)=(nonce, cipherthext, tag)
            # verify mac
            mac, aes = data.split()
            try:
                node.connected[receiver_username][3].hexverify(mac)
                print('mac OK')
            except:
                print('mac NOT OK')
                #to delete user in connected and return
                node.connected.pop(receiver_username)
            #verify signature
            nonce, ciphertext, tag = aes.split('*')
            ret = aes_decrypt(nonce,ciphertext, tag, node.connected[receiver_username][3])
            if ret != 0:
                #aes gone well
                #verify sign in ret
                key = RSA.import_key(node.connected[receiver_username][2])
                h = SHA256.new(ret)
                try:
                    pkcs1_15.new(key).verify(h,ret)
                    print("signature gone well")
                    node.connected[receiver_username][4]=0
                except:
                    print("signature gone wrong")
                    node.connected.pop(receiver_username)'''
    else:
        print('{}: {}'.format(event, data))



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


    first_half = get_random_string(8) #genero chiave
    node.connected[receiver][2] = first_half
    #first message
    x = username + ' ' + first_half
    print(x)
    key_ = RSA.import_key(node.connected[receiver][1]) #prelevo chiave pubblica di bob
    cipher = PKCS1_OAEP.new(key_)

    encrypted = cipher.encrypt(bytes(x, 'utf-8')) #chiave cifrata con chiave pubblica di bob
    print('cifrato ', encrypted)

    node_.send_to_node(node.connected[receiver][0], bytes('init1 ','utf-8') + encrypted)        #invio il messaggio cifrato

    '''#firmo x
    digest = s256.new(bytes(x, 'utf-8'))
    # devo firmare con la chiave privata di alice
    filename = username +'.pem'
    with open(filename, 'r') as key_file:
        private = RSA.import_key(key_file.read())
    signature = pkcs1_15.new(private).sign(digest)

    #Genero un MAC
    h = HMAC.new(bytes(comunication_secret, 'utf-8'), digestmod=SHA256)
    h.update(bytes(x, 'utf-8'))
    mac = h.hexdigest()
    #Cifro la firma con AES
    aes_cipher = AES.new(bytes(comunication_secret, 'utf-8'), AES.MODE_EAX)
    nonce = aes_cipher.nonce
    ciphertext, tag = aes_cipher.encrypt_and_digest(signature)

    #invio tutto al ricevente
    to_send = mac +' '+ str(nonce)+'*'+str(ciphertext)+'*'+str(tag)
    node_.send_to_node(node.connected[receiver][0], bytes(to_send,'utf-8'))  # invio la chiave cifrata'''

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
            if  (choice[1] not in node.connected) or (node.connected[choice[1]][3] == 0):
                # tentativo di connessione all'utente
                tupla = connect_to_contact(choice[1], socket)
                # !! POINT: possiamo garantire che i dati ricevuti siano corretti per quell' utente?
                # 1) trudy non ha manipolato i dati scambiandoli con quelli di qualcun altro
                if tupla != '0':
                    address = tupla.split(" ")
                    # mi connetto al nodo destinatario con i dati forniti dal server
                    node.connect_with_node(str(address[1]), int(address[2]))
                    id_user.update({id:choice[1]})
                    print(id_user)
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
                str_tosend = ': ' + msg + ' [' + tstamp + ']'

                #CIFRATURA

                #key_crypt = RSA.import_key(node.connected[receiver][1])
                cipher_aes = AES.new(bytes(node.connected[receiver][2], 'utf-8'), AES.MODE_EAX) #valutare se trasformare in bytes
                nonce = cipher_aes.nonce
                #str_encrypted = chiper_rsa.encrypt(bytes(str_tosend, 'utf-8'))
                ciphertext, tag = cipher_aes.encrypt_and_digest(bytes(str_tosend, 'utf-8'))
                print('nonce', type(nonce))
                print('ciphertext', type(ciphertext))
                print('tag',type(tag))
                userLen = len(args.username)
                if userLen < 10:
                    userLen = '0'+str(userLen)
                ast = bytes('*', 'utf-8')
                aes = {'ciphertext':ciphertext,
                       'nonce':nonce,
                       'tag':tag,
                       'username':args.username}

                json_data = str(aes)
                print(aes)
                node.send_to_node(node.connected[receiver][0], json_data )
                continue
            else:
                print("Specified user is not connected, please connect first to the user with 'connect' command\n")
                continue

        else:
            print('Please, use one of te specified command')

