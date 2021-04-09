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
import time
import threading


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


def generateTree(data):
    c = (
        Tree(init_opts=opts.InitOpts(theme=ThemeType.WHITE))
            .add("", data, symbol_size=10, orient="TB")
            .set_global_opts(title_opts=opts.TitleOpts(title="Tree-Nodes"))
            .render("tree_Node.html")
    )


def csvToDict(file):
    nodes_dict = {}
    csv = pd.read_csv(file, dtype=str)
    for node_id, father_id in csv.values:
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
    return _dataFormatterHelp(root_node)


def run():
    nodes = csvToDict("NodeLink.csv")
    root_list = findRootsByDict(nodes)
    data_gen = []
    for root_str in root_list:
        root = dataConstructor(root_str, nodes)
        res = dataFormatter(root)
        print(res)
        data_gen.append(res)
    generateTree(data_gen)


if __name__ == '__main__':
    run()
    # nodes = csvToDict("NodeLink.csv")
    # root_list = findRootsByDict(nodes)
    # data_gen = []
    # for root_str in root_list:
    #     root = dataConstructor(root_str, nodes)
    #     res = dataFormatter(root)
    #     print(res)
    #     data_gen.append(res)
    # generateTree(data_gen)
