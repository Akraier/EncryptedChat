import socket as sk
from Crypto.PublicKey import RSA

if __name__ == '__main__':
    host = sk.gethostname()
    port = 12345
    socket = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
    socket.connect((host, port))
    socket.sendall(bytes('Ciao bella!', 'utf-8'))
    print('aooooo')
    ricevuto = socket.recv(1024)
    print(ricevuto)
    socket.close()

