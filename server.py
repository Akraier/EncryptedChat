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

def login(username):
    print("sono nella login\n")
    file_registrati = open('./UtentiRegistrati.txt', 'r')
    riga_file = file_registrati.readline()
    #print("RIGA_FILE: ", riga_file)
    #print(" ",riga_file.split(" ")[0])

    while riga_file != '':
        print("RIGA_FILE: ", riga_file)
        print("riga file split: ", riga_file.split(" ")[0])
        print("USERNAME: ", username)
        if riga_file.split(" ")[0] != username:
            print("00000000000000000")
            riga_file = file_registrati.readline()
            continue
        random_string = get_random_string(16)               #genero stringa random per autenticazione del client
        print("stringa random: ", random_string)
        PubKeyClient = riga_file.split(" ")[1]              #prendo la chiave pubblica del client dal file per cifrare la stringa
        print('chiave pubblica: ', PubKeyClient)
        cipher_rsa = PKCS1_OAEP.new(PubKeyClient)
        message = cipher_rsa.encrypt(random_string)         # cifro con chiave pubblica del client e mando
        conn.sendall(bytes(message, 'utf-8'))
        break

    print("DOPO IL WHILE\n")
    if riga_file == '' :
        print("NON TROVATO!\n")
        conn.sendall(bytes('-1', 'utf-8'))              #caso di utente non registrato, restituisco errore
        return

    ricevuto = conn.recv(1024)
    if ricevuto == random_string:                       #se sono uguali autenticazione andata a buon fine, invio 1
        conn.sendall(bytes('1', 'utf-8'))
    else:                                               #altrimenti errore di autenticazione (-1)
        conn.sendall(bytes('-1', 'utf-8'))



def get_random_string(length):
    letters = string.ascii_letters
    result_str = ''.join(random.choice(letters) for i in range(length))
    #print("Random string is:", result_str)
    return result_str

def signup(username):
    #riceve chiave pubblica
    key_public_client = conn.recv(2048)

    #genera stringa casuale e la invia
    stringa_casuale = get_random_string(512) #512 lettere ovvero 4096 bit (?)
    conn.sendall(bytes(stringa_casuale, 'utf-8'))

    #riceve stringa cifrata con key private del client
    stringa_cifrata = conn.recv(4096)

    cipher_rsa = PKCS1_OAEP.new(key_public_client)
    stringa_decifrata = cipher_rsa.decrypt(stringa_cifrata)

    if stringa_decifrata == stringa_casuale:
        #memorizzo username e chiave pubblica del nuovo utente
        f = open('UtentiRegistrati.txt', 'w')
        f.write(username+' '+key_public_client)
        f.close()

        socket.sendall(bytes('0', 'utf-8'))
    else:
        socket.sendall(bytes('1', 'utf-8'))

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
