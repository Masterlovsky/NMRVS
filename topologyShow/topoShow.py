#! /usr/bin/python3
"""
By mzl 2021.04.8 version 1.0
Used to show Topology of Nodes
"""
from pyecharts import options as opts
from pyecharts.charts import Tree
from pyecharts.globals import ThemeType
import numpy as np
import pandas as pd
import pymysql


class Node(object):
    def __str__(self) -> str:
        return "name: " + self.name + ", children number: " + str(len(self.children))

    def __init__(self, name: str, children: list):
        self.children = children
        self.name = name

    def getName(self):
        return self.name

    def setChild(self, child):
        if child == "":
            return
        self.children.append(child)


class DataBase(object):
    def __init__(self, user, passwd, host="localhost", port=3306):
        self.host = host
        self.port = port
        self.user = user
        self.passwd = passwd

    def readDatabase(self):
        conn = pymysql.connect(host=self.host, user=self.user, passwd=self.passwd, port=self.port, db="nmrvs",
                               charset="utf8")
        cursor = conn.cursor()
        select_sql = "select * from nmrvs.node_parent;"
        cursor.execute(select_sql)
        row_all = cursor.fetchall()
        conn.commit()
        cursor.close()
        conn.close()
        return row_all


def generateTree(data):
    """
    根据json数据生成树结构的html代码
    :param data:
    """
    c = (
        Tree(init_opts=opts.InitOpts(theme=ThemeType.WHITE))
            .add("", data, symbol_size=10, orient="TB")
            .set_global_opts(title_opts=opts.TitleOpts(title="Tree-Nodes"))
            .render("tree_Node.html")
    )


def csvToDict(file: str) -> dict:
    nodes_dict = {}
    csv = pd.read_csv(file, dtype=str)
    for node_id, father_id in csv.values:
        if father_id not in nodes_dict.keys():
            nodes_dict[father_id] = []
        nodes_dict[father_id].append(node_id)
    return nodes_dict


def dataBaseToDict(rolls: tuple) -> dict:
    """
    使用数据库中读取的条目构建父子关系字典
    :param rolls: 数据库中读取的条目，元组类型 (nodeid, parentid)
    :return: 父子关系字典
    """
    nodes_dict = {}
    for node_id, father_id in rolls:
        if father_id not in nodes_dict.keys():
            nodes_dict[father_id] = []
        nodes_dict[father_id].append(node_id)
    return nodes_dict


def findRootsByDict(nodes_dict: dict) -> list:
    root_l = []
    for key in nodes_dict.keys():
        if key not in sum(nodes_dict.values(), []):
            root_l.append(key)
    return root_l


def dataConstructor(root: str, node_dict: dict) -> Node:
    """
    根据根节点和父子关系字典生成树结构
    :param root: 根节点ID
    :param node_dict: 父子关系字典
    :return: 根节点Node
    """
    node_root = Node(root, [])
    for child in node_dict[root]:
        if child not in node_dict.keys():
            node_root.setChild(Node(child, []))
        else:
            node_root.setChild(dataConstructor(child, node_dict))
    return node_root


def _dataFormatterHelp(root_node: Node):
    res_dict = {"name": root_node.getName(), "children": [_dataFormatterHelp(child) for child in root_node.children]}
    return res_dict


def dataFormatter(root_node):
    """
    将树结构整理成pyecharts支持的层次嵌套json结构
    :param root_node: 根节点Node
    :return:
    """
    return _dataFormatterHelp(root_node)


def run():
    # nodes = csvToDict("NodeLink.csv")
    nodes = dataBaseToDict(DataBase("root", "m97z04l05").readDatabase())
    root_list = findRootsByDict(nodes)
    data_gen = []
    for root_str in root_list:
        root = dataConstructor(root_str, nodes)
        res = dataFormatter(root)
        print("structure:\n" + str(res))
        data_gen.append(res)
    generateTree(data_gen)


if __name__ == '__main__':
    run()
