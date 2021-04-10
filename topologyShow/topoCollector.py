#! /usr/bin/python3
"""
By mzl 2021.04.8 version 1.0
Used to show Topology of Nodes
"""
import threading
import time
import socket

ADDRESS = ("127.0.0.1", 9000)


def resolvePacket(data_hex):
    nodeID = ""
    parentID = ""
    return nodeID, parentID


def writeToCsv(nodeid, parenid):
    line = nodeid + "," + parenid + "\n"
    with open("NodeLink.csv", "a") as f:
        f.write(line)


if __name__ == '__main__':
    # 创建套接字
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # 绑定
    sock.bind(ADDRESS)
    print("waiting to receive messages...")

    while True:
        (data, addr) = sock.recvfrom(1024)
        text = data.decode('utf-8')
        if text == 'exit':
            break
        else:
            print('The client at {} says {!r}'.format(addr, text))
            text = 'Your data was {} bytes long'.format(len(data))
            data = text.encode('utf-8')
            sock.sendto(data, addr)

    # 关闭套接字
    sock.close()
