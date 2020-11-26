import socket as sk
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def login(username):
    esito = -1
    print("sono nella login")
    socket.sendall(bytes('2'+username, 'utf-8'))
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


def signup(username):
    key = RSA.generate(2048)  # client genera la chiave privata
    private_key = key.export_key()
    f = open(username + '.pem', 'wb')  # crea un file per salvarla
    f.write(private_key)
    f.close()

    public_key = key.publickey().export_key()  # generazione chiave pubblica
    # salvataggio chiave pubblica lato client ?

    # spedisco al server la mia chiave pubblica
    socket.send(public_key.encode())

    # aspetto stringa generata casualmente
    stringa = socket.recv(4096)

    # cifro con chiave privata del client
    cipher_rsa = PKCS1_OAEP.new(private_key)
    stringa_cifrata = cipher_rsa.decrypt(stringa)

    # invio la stringa cifrata al server
    socket.send(stringa_cifrata.encode())

    # aspetto l'ok
    esito = socket.recv(1024)

    if esito == 0:
        print("Registrazione avvenuta con successo")
        return
    else:
        print("Si è verificato un errore")

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
   # if login(username) == '-1':
   #     registrati()


''' def conn_to_server():
   try:
        socket = sk.socket(sk.AF_INET, sk.SOCK_STREAM) #creazione socket client
        socket.connect((indirizzo_server,porta_server)) #connessione al server
        print("Connessione al server effettuata")

        #creazione username e generazione key public e key private
        username = input("Inserire username:")
        socket.send(username, 'utf-8')


   except sk.error as errore:
        print("Connessione non riuscita"+errore)
'''

