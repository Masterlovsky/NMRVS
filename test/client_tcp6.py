import socket
import time

ADDRESS = ("::1", 9000)
if __name__ == '__main__':
    while True:
        client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        client.connect(ADDRESS)
        msg = input("msg: ")
        # msg = "0a111111111111111201"
        client.send(bytes.fromhex(msg))
        data = client.recv(1024).decode("utf-8")
        print(data)
