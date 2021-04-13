import socket
import time

ADDRESS = ("127.0.0.1", 9000)
if __name__ == '__main__':
    while True:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(ADDRESS)
        msg = input("msg: ")
        # msg = "0a1111111111111112"
        client.send(bytes.fromhex(msg))
        data = client.recv(1024).decode("utf-8")
        print(data)
