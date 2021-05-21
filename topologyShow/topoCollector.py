#! /usr/bin/python3
"""
By mzl 2021.04.8 version 1.0
Used to show Topology of Nodes
"""
import threading
import time
import socket

import pymysql

ADDRESS = ("::1", 9000)
MSG_PARENT = "0a"
MSG_PARENT_REMOVE = "0b"
DB_USER = "root"
DB_PASSWORD = "123456"


def resolvePacket(data_hex):
    """
    根据16进制字符串报文返回NodeID和ParentID
    :param data_hex: 0x0a1111111122222222
    :return: nodeID = 11111111 , parentID = 22222222
    """
    nodeID = data_hex[2:10]
    parentID = data_hex[10:18]
    nodeIsReal = data_hex[18:20]
    return nodeID, parentID, nodeIsReal


def writeToCsv(nodeid, parentid):
    line = nodeid + "," + parentid + "\n"
    with open("NodeLink.csv", "a") as f:
        f.write(line)


class DataBase(object):
    def __init__(self, user, passwd, host="localhost", port=3306):
        self.host = host
        self.port = port
        self.user = user
        self.passwd = passwd

    def writeToDataBase(self, node_id, parent_id, node_is_real):
        conn = pymysql.connect(host=self.host, user=self.user, passwd=self.passwd, port=self.port, db="nmrvs",
                               charset="utf8")
        cursor = conn.cursor()
        select_sql = "INSERT into node_parent(NodeID, ParentID, NodeIsReal) values(%s,%s,%s)" \
                     + " on DUPLICATE key UPDATE NodeID=%s,ParentID=%s,NodeIsReal=%s;"
        values = (node_id, parent_id, node_is_real, node_id, parent_id, node_is_real)
        # select_sql = "INSERT into node_parent(NodeID, ParentID)values('" + "00000011" + "','" + "00000001" + "')"\
        #              + " on DUPLICATE key UPDATE NodeID='" + "00000011" + "'," + "ParentID='" + "00000001" + "'; "
        cursor.execute(select_sql, values)
        # row_all = cursor.fetchall()
        conn.commit()
        cursor.close()
        conn.close()
        # print("row_all: " + str(row_all))

    def deleteByID(self, node_id):
        conn = pymysql.connect(host=self.host, user=self.user, passwd=self.passwd, port=self.port, db="nmrvs",
                               charset="utf8")
        cursor = conn.cursor()
        delete_sql = "DELETE from node_parent WHERE NodeID = {};".format(node_id)
        cursor.execute(delete_sql)
        conn.commit()
        cursor.close()
        conn.close()
        # print("row_all: " + str(row_all))


def run():
    # 创建套接字
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    # 绑定
    sock.bind(ADDRESS)
    # 监听
    sock.listen(1000)
    print("listening on " + str(ADDRESS) + ", waiting to receive messages...")
    flag = True
    while flag:
        try:
            client_socket, addr = sock.accept()
            receive_data = client_socket.recv(1024)
            # if receive_data.decode("utf-8") == "exit":
            #     flag = False
            data = receive_data.hex()
            db = DataBase(DB_USER, DB_PASSWORD)
            if data[0:2] == MSG_PARENT:
                nodeId, parentId, isReal = resolvePacket(data)
                # writeToCsv(nodeId, parentId)
                db.writeToDataBase(nodeId, parentId, isReal)
            elif data[0:2] == MSG_PARENT_REMOVE:
                nodeId = data[2:10]
                db.deleteByID(nodeId)
            print("from: " + str(addr) + " receive: " + data)
            # client_socket.send("success!".encode("utf-8"))
            client_socket.close()
        except Exception as err:
            print(err)
            break
    # 关闭套接字
    sock.close()


if __name__ == '__main__':
    run()
    # db = DataBase("root", "m97z04l05")
    # db.deleteByID("00000003")
    # # db.writeToDataBase("00000002", "00000001", "01")
