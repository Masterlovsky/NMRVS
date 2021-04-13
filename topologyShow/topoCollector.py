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
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 绑定
    sock.bind(ADDRESS)
    # 监听
    sock.listen(1000)
    print("waiting to receive messages...")
    flag = True
    while flag:
        client_socket, addr = sock.accept()
        receive_data = client_socket.recv(1024)
        if receive_data.decode("utf-8") == "exit":
            break
        print("from: " + str(addr) + " receive: " + receive_data.decode("utf-8"))
        client_socket.send("success!".encode("utf-8"))
        client_socket.close()
    # 关闭套接字
    sock.close()
