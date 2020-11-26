import socket as sk
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

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
            conn.sendall(bytes('Thank you for connecting', 'utf-8'))
        except:
            conn.close()
            print("Connection closed by", addr)
            # Quit the thread.
            sys.exit()
