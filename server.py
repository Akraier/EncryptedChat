import socket as sk
import sys
import random
import string
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def login(username):
    file_registrati = open('UtentiRegistrati.txt', 'r')
    riga_file = file_registrati.readline()
    while riga_file != None:
        if riga_file.split(" ")[0] != username:
            riga_file = file_registrati.readline()
            continue
        #TODO! generare stringa random da mandare al client e valutare la risposta da parte del client

def get_random_string(length):
    letters = string.ascii_letters
    result_str = ''.join(random.choice(letters) for i in range(length))
    #print("Random string is:", result_str)
    return result_str

def signup(username):
    #riceve chiave pubblica
    key_public_client = socket.recv(2048)

    #genera stringa casuale e la invia
    stringa_casuale = get_random_string(512) #512 lettere ovvero 4096 bit (?)
    socket.sendall(bytes(stringa_casuale, 'utf-8'))

    #riceve stringa cifrata con key private del client
    stringa_cifrata = socket.recv(4096)

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

    file_registrati = open('UtentiRegistrati.txt', 'w')
    file_registrati.close()

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
                login(data.decode("utf-8")[1:len(data.decode("utf-8"))-1])

            conn.sendall(bytes('Thank you for connecting', 'utf-8'))

        except:
            conn.close()
            print("Connection closed by", addr)
            # Quit the thread.
            sys.exit()
