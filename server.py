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
    # scorro il file per vedere se l'username è registrato
    while riga_file != '':
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


def login(username, indirizzo):
    print("sono nella login\n")
    global secret
    file_registrati = open('./UtentiRegistrati.txt', 'r')
    riga_file = file_registrati.readline()

    if riga_file != '':
        print("Genero stringa di autenticazione...")
        # genero stringa random per autenticazione del client
        random_string = get_random_string(64)
        secret = bytes(random_string,'utf-8')
        print("Recupero chiave pubblica del client...")
        # prendo la chiave pubblica del client dal file per cifrare la stringa
        PubKey = search_pubKey(username)
        PubKeyClient_bytes = bytes(PubKey, 'utf-8')
        print('chiave pubblica: ', PubKey)
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(PubKeyClient_bytes))
        print("Cifratura con RSA della stringa...")
        # cifro con chiave pubblica del client e mando
        message = cipher_rsa.encrypt(secret)
        conn.sendall(bytes('1', 'utf-8'))
        print("Invio stringa cifrata...")
        conn.sendall(message)

    elif riga_file == '':
        # caso di utente non registrato, restituisco errore
        print("NON TROVATO!\n")
        conn.sendall(bytes('-1', 'utf-8'))
        return

    # ricevo stringa random cifrata dal client
    ricevuto = conn.recv(1024)
    print("RICEVUTO: ", ricevuto)
    messaggio = decifratura(ricevuto)
    print("stringa random dopo decifratura: ", messaggio)

    host_port = conn.recv(1024)
    print("host port:", host_port.decode('utf-8'))
    if messaggio == bytes(random_string, 'utf-8'):
        # se sono uguali autenticazione andata a buon fine, invio 1
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

        buffer_login = '2' + username + '1' + random_string + '1'
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
    print("Ricevo chiave pubblica dal client...")
    key_public_client_PEM = conn.recv(2048)

    # Recupero la chiave dal formato PEM
    key_public_client = RSA.import_key(key_public_client_PEM)
    #genera stringa casuale
    print("Genero stringa casuale di conferma...")
    stringa_casuale = get_random_string(64)
    bytes_stringa_casuale = bytes(stringa_casuale, 'utf-8')

    #Cripto la stringa generata casualmente con la chiave pubblica del client
    print("Cifratura della stringa con chiave pubblica dell'utente...")
    encryptor = PKCS1_OAEP.new(key_public_client)
    stringa_cifrata = encryptor.encrypt(bytes_stringa_casuale)

    print("Invio stringa cifrata...")
    conn.sendall(stringa_cifrata) #invio la stringa cifrata

    print("Ricevo MAC generato dal client...")
    mac_client = conn.recv(2048)
    print("Genero MAC...")
    buffer_mac = buffer + key_public_client_PEM.decode('utf-8') + stringa_casuale
    mac = genera_mac(bytes_stringa_casuale, buffer_mac)
    print("Verifica MAC...")
    if mac == mac_client.decode('utf-8'):
        conn.sendall(bytes(mac, 'utf-8'))
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

#dichiarazioni variabili globali
loggato = 0
nickname = ""
secret = ""
if __name__ == '__main__':

    # generazioni chiave privata per il server
    key = RSA.generate(2048)
    private_key = key.export_key()
    f = open('serverPrivKey.pem', 'wb')
    f.write(private_key)
    f.close()

    # generazione chiave pubblica
    public_key = key.publickey().export_key()
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

                except:
                    conn.close()
                    print("Connection closed by", addr)
                    # Quit the thread.
                    sys.exit()