import socket as sk
import sys
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


if __name__ == '__main__':

    key = RSA.generate(2048)            #generazioni chiave privata per il server
    private_key = key.export_key()
    f = open('serverPrivKey.pem', 'wb')          #essendo always on si può fare all'inizio e pace
    f.write(private_key)
    f.close()

    public_key = key.publickey().export_key()  #generazione chiave pubblica
    f = open('servePubKey.pem', 'wb')
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
            if data.decode("utf-8")[0] == '2':
                login(data.decode("utf-8")[1:len(data.decode("utf-8"))-1])
            conn.sendall(bytes('Thank you for connecting', 'utf-8'))
        except:
            conn.close()
            print("Connection closed by", addr)
            # Quit the thread.
            sys.exit()
