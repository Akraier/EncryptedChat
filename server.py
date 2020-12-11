import socket as sk
import sys
import os
import random
import string
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256

def get_random_string(length):
    # Random string with the combination of lower and upper case
    letters = string.ascii_letters
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

def decifratura(mex):
    f = open('serverPrivKey.pem', 'r')  # recupero chiave privata server
    key = RSA.import_key(f.read())
    f.close()
    cipher_rsa = PKCS1_OAEP.new(key)
    mex = cipher_rsa.decrypt(mex)
    return mex

def genera_mac(secret_, buffer):

    print("Il segreto è:", secret_)
    h = HMAC.new(secret_, bytes(buffer,'utf-8'), digestmod=SHA256)
    mac = h.hexdigest()
    print("Il mac generato è:", mac)

    return mac

def logout(username):
    file_path = "./connessi/" + username + ".txt"
    os.remove(file_path)
    conn.close()


def search_pubKey(username):
    registrati = open('./UtentiRegistrati.txt', 'r')
    riga_file = registrati.readline()
    #if username in registrati.read():
    while riga_file != '':                                 #scorro il file per vedere se l'username è registrato
        if riga_file.split(" ")[0] != username:
            riga_file = registrati.readline()
            continue
        PubKeyClient = '-----BEGIN PUBLIC KEY-----\n'
        for i in range(8):
            riga = registrati.readline()
            PubKeyClient = PubKeyClient + riga
        registrati.close()
        return PubKeyClient
    registrati.close()
    return
        #elif riga_file.split()[0] == username:
           # break



def login(username, indirizzo):
    print("sono nella login\n")
    global secret
    file_registrati = open('./UtentiRegistrati.txt', 'r')
    riga_file = file_registrati.readline()

    if riga_file != '':

        random_string = get_random_string(64) #genero stringa random per autenticazione del client
        secret = bytes(random_string,'utf-8')
        #print("stringa random: ", random_string)
        PubKey = search_pubKey(username)#prendo la chiave pubblica del client dal file per cifrare la stringa
        PubKeyClient_bytes = bytes(PubKey, 'utf-8')
        print('chiave pubblica: ', PubKey)
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(PubKeyClient_bytes))
        message = cipher_rsa.encrypt(secret)         # cifro con chiave pubblica del client e mando
        #print('stringa random cifrata: ', message)
        conn.sendall(bytes('1', 'utf-8'))
        conn.sendall(message)

    elif riga_file == '':
        print("NON TROVATO!\n")
        conn.sendall(bytes('-1', 'utf-8'))              #caso di utente non registrato, restituisco errore
        return

    ricevuto = conn.recv(1024)                            #ricevo stringa random cifrata dal client
    print("RICEVUTO: ", ricevuto)
    messaggio = decifratura(ricevuto)
    print("stringa random dopo decifratura: ", messaggio)

    host_port = conn.recv(1024)
    print("host port:", host_port.decode('utf-8'))
    if messaggio == bytes(random_string, 'utf-8'):          #se sono uguali autenticazione andata a buon fine, invio 1

        conn.sendall(bytes('1', 'utf-8'))
        global loggato
        global nickname
        loggato = 1
        nickname = username
        fd_user = open("./connessi/"+username+".txt", 'w')

        fd_user.write(indirizzo + host_port.decode('utf-8'))

        fd_user.close()

        mac_client = conn.recv(64)
        print("mac client ricevuto:", mac_client)

        print("Pre riempimento")
        buffer_login = '2' + username + '1' + random_string + '1'
        print("buffer login riempito")
        mac = genera_mac(secret, buffer_login)
        print("mac generato")

        if mac == mac_client.decode('utf-8'):
            conn.sendall(bytes(mac, 'utf-8'))
            print("Utente loggato con successo")

        else:
            conn.sendall(b'0')
            print("Tentativo di login rifiutato")
    else:
        conn.sendall(b'errore in fase di login, messaggio errato')
        print("Tentativo di login rifiutato")

def signup(username, buffer):

    #riceve chiave pubblica
    key_public_client_PEM = conn.recv(2048)
    #key_public_client_PEM = key_public_client_PEM.decode('utf-8')

    key_public_client = RSA.import_key(key_public_client_PEM) #Recupero la chiave dal formato PEM
    #print("Questa è la chiave:",key_public_client) #in formato RsaKey
    #genera stringa casuale
    stringa_casuale = get_random_string(64)
    bytes_stringa_casuale = bytes(stringa_casuale, 'utf-8')


    #Cripto la stringa generata casualmente con la chiave pubblica del client
    encryptor = PKCS1_OAEP.new(key_public_client)
    stringa_cifrata = encryptor.encrypt(bytes_stringa_casuale)


    conn.sendall(stringa_cifrata) #invio la stringa cifrata

    #print("Stringa inviata")
    #riceve stringa decifrata con key private del client
    #stringa_decifrata = conn.recv(2048)
    #stringa_decifrata = stringa_decifrata.decode('utf-8')

    #print("Stringa decriptata dal client: ",stringa_decifrata)
    #print("Stringa generata inizialmente: ",stringa_casuale)

    mac_client = conn.recv(2048)

    buffer_mac = buffer + key_public_client_PEM.decode('utf-8') + stringa_casuale
    mac = genera_mac(bytes_stringa_casuale, buffer_mac)

    if mac == mac_client.decode('utf-8'):
        conn.sendall(bytes(mac, 'utf-8'))
        #print("Stringhe uguali")
        #memorizzo username e chiave pubblica del nuovo utente
        f = open('UtentiRegistrati.txt', 'a')

        f.write(username+" "+key_public_client_PEM.decode('utf-8')+"\n")
        f.close()

        print("Registrazione ok")

        f = open('UtentiRegistrati.txt', 'r')
        riga_letta = f.read()


        chiave = riga_letta.split(' ')[1]


        chiave_bytes = bytes(chiave,'utf-8')


        f.close()
    else:
        conn.sendall(b'errore')

def comunication_request(username):
    #devo cercare l'username nel file degli utenti
    registered = open('./UtentiRegistrati.txt', 'r')
    reg_r = registered.read()
    if username in reg_r:
        #solo se l'utente e' registrato provo ad accedere al file
        file_path = './connessi/' + username + '.txt'
        try:
            online = open(file_path, 'r')
        except:
            print("File '" + file_path + "' does not exist.")
            return
        node = online.read()
        #ip_port va mandato tutto al client insieme alla chiave pubblica
        pubKey = search_pubKey(username)
        to_send = node + ' ***' + pubKey + '***'
        print('tosend ', to_send)
        print('stringa >'+to_send+' connect '+username)
        mac_ = genera_mac(secret, to_send+' connect '+username)
        conn.sendall(bytes(to_send + '///' + mac_, "utf-8"))
loggato = 0
nickname = ""
secret = ""
if __name__ == '__main__':

    key = RSA.generate(2048)            #generazioni chiave privata per il server
    private_key = key.export_key()
    f = open('serverPrivKey.pem', 'wb')          #essendo always on si può fare all'inizio e pace
    f.write(private_key)
    f.close()

    public_key = key.publickey().export_key()  #generazione chiave pubblica
    f = open('serverPubKey.pem', 'wb')
    f.write(public_key)
    f.close()

    file_registrati = open('UtentiRegistrati.txt', 'w')
    file_registrati.close()

    host = sk.gethostname()
    port = 12345
    socket = sk.socket()
    socket.bind((host, port))
    socket.listen(10)
    while 1:
        conn, addr = socket.accept()
        pid = os.fork()
        if pid == -1:
            print('fork error')
            exit(1)
        elif pid > 0:
            # father
            conn.close()
        elif pid == 0:
            # child
            socket.close()
            print('Got connection from ', addr[0], '(', addr[1], ')')
            ip = bytes(addr[0], 'utf-8')
            connection = " " + ip.decode('utf-8') + " "

            while True:
                try:
                    data = conn.recv(1024)
                    if not data:
                        conn.close()
                    buffer = data.decode("utf-8")
                    command = buffer.split()
                    print("Request "+data.decode("utf-8"))
                    if command[0][0] == '1':
                        signup(command[0][1:len(command[0])], buffer)
                    if command[0][0] == '2':
                        login(command[0][1:len(command[0])], connection)
                    if command[0][0] == '3':
                        logout(command[0][1:len(command[0])])
                    if (len(command) > 1) and (command[0] == 'connect'):
                        print("Richiesta dati di "+command[1]+" da "+nickname+", utente verificato.")
                        comunication_request(command[1])
                    # conn.sendall(bytes('Thank you for connecting', 'utf-8'))

                except:
                    conn.close()
                    print("Connection closed by", addr)
                    # Quit the thread.
                    sys.exit()