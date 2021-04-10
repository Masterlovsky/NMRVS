import socket
import time

ADDRESS = ("127.0.0.1", 9000)
if __name__ == '__main__':

    while True:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        data = input("input: ")
        client.sendto(data.encode(encoding="utf-8"), ADDRESS)
        recv, addr = client.recvfrom(1024)
        print(recv.decode(encoding="UTF-8"), "from", addr)
