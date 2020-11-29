import socket as sk
import sys
import random
import string
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def get_random_string(length):
    # Random string with the combination of lower and upper case
    letters = string.ascii_letters
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

def decifratura(messaggio):
    f = open('serverPrivKey.pem', 'r')  # recupero chiave privata server
    key = RSA.import_key(f.read())
    f.close()
    cipher_rsa = PKCS1_OAEP.new(key)
    messaggio = cipher_rsa.decrypt(messaggio)
    return messaggio

def login(username):
    print("sono nella login\n")
    file_registrati = open('./UtentiRegistrati.txt', 'r')
    riga_file = file_registrati.readline()

    while riga_file != '':                                 #scorro il file per vedere se l'username è registrato
        print("riga file split: ", riga_file.split(" ")[0])
        print("USERNAME: ", username)
        if riga_file.split(" ")[0] != username:
            riga_file = file_registrati.readline()
            continue
        random_string = get_random_string(16)               #genero stringa random per autenticazione del client
        print("stringa random: ", random_string)
        PubKeyClient = riga_file.split(" ")[1]              #prendo la chiave pubblica del client dal file per cifrare la stringa
        print('chiave pubblica: ', PubKeyClient)
        cipher_rsa = PKCS1_OAEP.new(PubKeyClient)
        message = cipher_rsa.encrypt(random_string)         # cifro con chiave pubblica del client e mando
        print('stringa random cifrata: ', message)
        conn.sendall(bytes(message, 'utf-8'))
        break

    if riga_file == '':
        print("NON TROVATO!\n")
        conn.sendall(bytes('-1', 'utf-8'))              #caso di utente non registrato, restituisco errore
        return

    ricevuto = conn.recv(1024)                            # ricevo stringa random cifrata dal client
    message = decifratura(ricevuto.decode('utf-8'))

    if message == random_string:                        #se sono uguali autenticazione andata a buon fine, invio 1
        conn.sendall(bytes('1', 'utf-8'))
    else:                                               #altrimenti errore di autenticazione (-1)
        conn.sendall(bytes('-1', 'utf-8'))



def get_random_string(length):
    letters = string.ascii_letters
    result_str = ''.join(random.choice(letters) for i in range(length))
    #print("Random string is:", result_str)
    return result_str

def signup(username):
    print("Sono nella signup")
    #riceve chiave pubblica
    key_public_client = conn.recv(2048)
    key_public_client.decode('utf-8')
    #key_public_client = RSA.importKey(conn.recv(2048), passphrase=None)
    #key_public_client.decode('utf-8')

    print(key_public_client)
    #print(key_public_client.decode('utf-8'))
    print("ricevuta chiave pubblica")

    #genera stringa casuale e la invia
    stringa_casuale = "aaaaaaaaaaaaaaaa"
    print("Ecco la stringa generata: "+stringa_casuale)
    conn.sendall(bytes(stringa_casuale, 'utf-8'))

    print("Stringa inviata")
    #riceve stringa decifrata con key private del client
    stringa_decifrata = conn.recv(16)
    stringa_decifrata = stringa_decifrata.decode('utf-8')

    print("Stringa ricevuta")

    cipher_rsa = PKCS1_OAEP.new(key_public_client)
   # stringa = cipher_rsa.encrypt(stringa_decifrata)


    print("Stringa decriptata dal client: "+stringa_decifrata)
    print("Stringa generata inizialmente: "+stringa_casuale)
    if stringa_decifrata == stringa_casuale:
        print("Stringhe uguali")
        #memorizzo username e chiave pubblica del nuovo utente
        f = open('UtentiRegistrati.txt', 'w')
        f.write(username+' '+key_public_client.decode('utf-8'))
        f.close()

        f = open('UtentiRegistrati.txt', 'r')
        riga_letta = f.read()
        print("Credenziali registrate: "+riga_letta)
        f.close()

        conn.sendall(bytes('0', 'utf-8'))
        print("Comunicazione al server effettuata")
    else:
        conn.sendall(bytes('1', 'utf-8'))
        print("Brutta notizia al server inviata")

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

    #file_registrati = open('UtentiRegistrati.txt', 'w')
    #file_registrati.close()

    host = sk.gethostname()
    port = 12345
    socket = sk.socket()
    socket.bind((host, port))
    socket.listen(10)
    conn, addr = socket.accept()
    print('Got connection from ', addr[0], '(', addr[1], ')')
    while True:
        try:
            data = conn.recv(1024)
            if not data:
                conn.close()
            print(data.decode("utf-8"))
            if data.decode("utf-8")[0] == '1':
                signup(data.decode("utf-8")[1:len(data.decode("utf-8"))-1])
            if data.decode("utf-8")[0] == '2':
                login(data.decode("utf-8")[1:len(data.decode("utf-8"))])

            conn.sendall(bytes('Thank you for connecting', 'utf-8'))

        except:
            conn.close()
            print("Connection closed by", addr)
            # Quit the thread.
            sys.exit()
