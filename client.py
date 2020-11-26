import socket as sk
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def login(username):
    esito = -1
    print("sono nella login")
    socket.sendall(bytes(username, 'utf-8'))
    ricevuto = socket.recv(1024)
    if ricevuto == '-1':            #in caso di utente non registrato il server risponde con codice -1?
        return esito

    f = open(username+'.pem', 'r')      #recupero la mia chiave privata
    private_key = RSA.import_key(f.read())
    f.close()

    cipher_rsa = PKCS1_OAEP.new(private_key)
    message = cipher_rsa.decrypt(ricevuto)  #decifro il messaggio (random) ricevuto dal server con la mia chiave privata

    f = open('serverPubKey.pem', 'r')
    serverPub_key = RSA.import_key(f.read())            #recupero chiave pubblica del server
    cipher_rsa = PKCS1_OAEP.new(serverPub_key)
    message = cipher_rsa.encrypt(message)               #cifro con chiave pubblica del server e mando
    socket.sendall(bytes(message, 'utf-8'))

    ricevuto = socket.recv(1024)             #se l'autenticazione è andata a buon fine il server me lo segnala
    if ricevuto == '1':                      #inviando 1 (da vedere se vogliamo cifrare anche questo), altrimenti
        return ricevuto                      #qualsiasi cosa mi invia capisco che c'è stato un errore e ritorno errore(-1)
    else:
        return esito



if __name__ == '__main__':

    username = input("inserisci il tuo username: ")

    host = sk.gethostname()
    port = 12345
    socket = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
    socket.connect((host, port))
    socket.sendall(bytes('Ciao bella!', 'utf-8'))
    ricevuto = socket.recv(1024)
    print(ricevuto)
    #socket.close()      #da togliere, farei una funzione logout per eliminare l'indirizzo ip
                        #dal server prima di chiudere
    login(username)


