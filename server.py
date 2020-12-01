import socket as sk
import sys
import os
import random
import string
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

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

def logout(username):
    file_path = "./connessi/" + username + ".txt"
    os.remove(file_path)
    conn.close()

def login(username, indirizzo):
    print("sono nella login\n")
    file_registrati = open('./UtentiRegistrati.txt', 'r')
    riga_file = file_registrati.readline()

    while riga_file != '':                                 #scorro il file per vedere se l'username è registrato
        if riga_file.split(" ")[0] != username:
            riga_file = file_registrati.readline()
            continue
        random_string = get_random_string(16)               #genero stringa random per autenticazione del client
        print("stringa random: ", random_string)
        PubKeyClient= '-----BEGIN PUBLIC KEY-----\n'
        for i in range(8):
            PubKeyClient = PubKeyClient + file_registrati.readline() #prendo la chiave pubblica del client dal file per cifrare la stringa
        PubKeyClient_bytes = bytes(PubKeyClient, 'utf-8')
        print('chiave pubblica: ', PubKeyClient)
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(PubKeyClient_bytes))
        message = cipher_rsa.encrypt(bytes(random_string,'utf-8'))         # cifro con chiave pubblica del client e mando
        print('stringa random cifrata: ', message)
        conn.sendall(bytes('1', 'utf-8'))
        conn.sendall(message)
        break

    if riga_file == '':
        print("NON TROVATO!\n")
        conn.sendall(bytes('-1', 'utf-8'))              #caso di utente non registrato, restituisco errore
        return

    ricevuto = conn.recv(1024)                            # ricevo stringa random cifrata dal client
    print("RICEVUTO: ", ricevuto)
    messaggio = decifratura(ricevuto)
    print("stringa random dopo decifratura: ", messaggio)

    if messaggio == bytes(random_string, 'utf-8'):          #se sono uguali autenticazione andata a buon fine, invio 1
        fd_user = open("./connessi/"+username+".txt", 'w')
        fd_user.write(indirizzo)
        fd_user.close()
        conn.sendall(bytes('1', 'utf-8'))
        print("MANDATO 1!!!!!!!!!!!!!!!!!!!")
    else:                                               #altrimenti errore di autenticazione (-1)
        conn.sendall(bytes('-1', 'utf-8'))


def signup(username):
    print("Sono nella signup")
    #riceve chiave pubblica
    key_public_client_PEM = conn.recv(2048)
    #key_public_client_PEM = key_public_client_PEM.decode('utf-8')

    print(key_public_client_PEM)
    #print("ricevuta chiave pubblica")

    key_public_client = RSA.import_key(key_public_client_PEM) #Recupero la chiave dal formato PEM
    #print("Questa è la chiave:",key_public_client) #in formato RsaKey
    #genera stringa casuale
    stringa_casuale = get_random_string(16)
    bytes_stringa_casuale = bytes(stringa_casuale, 'utf-8')
    #print("Stringa generata: ",bytes_stringa_casuale)

    #Cripto la stringa generata casualmente con la chiave pubblica del client
    encryptor = PKCS1_OAEP.new(key_public_client)
    stringa_cifrata = encryptor.encrypt(bytes_stringa_casuale)
    print("La stringa è stata cifrata correttamente :", stringa_cifrata)

    conn.sendall(stringa_cifrata) #invio la stringa cifrata

    #print("Stringa inviata")
    #riceve stringa decifrata con key private del client
    stringa_decifrata = conn.recv(2048)
    stringa_decifrata = stringa_decifrata.decode('utf-8')

    #print("Stringa decriptata dal client: ",stringa_decifrata)
    #print("Stringa generata inizialmente: ",stringa_casuale)

    if stringa_decifrata == stringa_casuale:
        #print("Stringhe uguali")
        #memorizzo username e chiave pubblica del nuovo utente
        f = open('UtentiRegistrati.txt', 'a')
        print("Chiave in formato stringa:",key_public_client_PEM)
        f.write(username+" "+key_public_client_PEM.decode('utf-8'))
        f.close()

        print("Registrazione ok")

        f = open('UtentiRegistrati.txt', 'r')
        riga_letta = f.read()
        print("Credenziali registrate: ", riga_letta)

        chiave = riga_letta.split(' ')[1]
        print("Chiave recuperata dal file",chiave)

        chiave_bytes = bytes(chiave,'utf-8')
        print("Chiave in formato bytes:",chiave_bytes)

        f.close()

        conn.sendall(bytes('0', 'utf-8'))
        #print("Comunicazione al server effettuata")
    else:
        conn.sendall(bytes('1', 'utf-8'))
        print("Brutta notizia al server inviata")


def comunication_request(username):
    #devo cercare l'username nel file degli utenti
    registered = open('./UtentiRegistrati.txt', 'r')
    reg_r = registered.read()
    if username in reg_r:
        file_path = './connessi/' + username + '.txt'
        try:
            online = open(file_path, 'r')
        except:
            print("File '" + file_path + "' does not exist.")
            return
        ro = online.read()


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
    conn, addr = socket.accept()
    print('Got connection from ', addr[0], '(', addr[1], ')')
    ip = bytes(addr[0], 'utf-8')
    port_host = str(addr[1])
    connection = " " + ip.decode('utf-8') + " " + port_host
    while True:
        try:
            data = conn.recv(1024)
            if not data:
                conn.close()
            r = data.decode("utf-8")
            command = r.split()
            print(data.decode("utf-8"))
            if command[0][0] == '1':
                signup(command[0][1:len(command[0])])
            if command[0][0] == '2':
                login(command[0][1:len(command[0])], connection)
            if command[0][0] == '3':
                logout(command[0][1:len(command[0])])
            if command[0] == 'connect':
                #command[1] esiste
                comunication_request(command[1])
            # conn.sendall(bytes('Thank you for connecting', 'utf-8'))

        except:
            conn.close()
            print("Connection closed by", addr)
            # Quit the thread.
            sys.exit()