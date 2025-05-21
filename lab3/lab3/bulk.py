import sys
import string
import socket
import time

def server(port):
    s = socket.socket()
    fp = open('server-output.dat', 'w')
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    s.bind(('0.0.0.0', int(port)))
    s.listen(3)
    
    cs, addr = s.accept()
    print(addr)
    
    while True:
        data = cs.recv(1000)
        if data:
            fp.write(data.decode())
        else:
            break

    s.close()
    fp.close()

def client(ip, port):
    s = socket.socket()
    fp = open('client-input.dat', 'r')
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1) # Disable Nagle
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 0) # Disable Keepalive
    s.connect((ip, int(port)))
    
    while True:
        data = fp.read(1000)
        if data:
            s.send(data.encode())
        else:
            break

    time.sleep(2)
    s.close()
    fp.close()

        
if __name__ == '__main__':
    if sys.argv[1] == 'server':
        server(sys.argv[2])
    elif sys.argv[1] == 'client':
        client(sys.argv[2], sys.argv[3])
