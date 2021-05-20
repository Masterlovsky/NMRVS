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
import json

ROOT_STR = "00000000"


class Node(object):
    def __str__(self) -> str:
        return "name: " + self.name + ", children number: " + str(len(self.children))

    def __init__(self, name: str, children: list, is_real: str):
        self.children = children
        self.name = name
        self.isReal = is_real

    def getName(self):
        return self.name

    def getVal(self):
        return self.isReal

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


class DateEncoding(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, opts.LabelOpts):
            return str(o)


def generateTree(data: list):
    """
    根据json数据生成树结构的html代码
    :param data:
    """
    tree_data = {"name": "根节点管理系统", "children": [],
                 "label": opts.LabelOpts(font_size=14, font_weight="bold", horizontal_align="center",
                                         vertical_align="center", distance=10)}
    for series in data:
        tree_data["children"].append(series)
    c = (
        Tree(init_opts=opts.InitOpts(theme=ThemeType.WHITE, page_title="ResolveNodes", chart_id="masterlovsky_tree_01"))
            .add("",
                 [tree_data],
                 symbol="emptyCircle",
                 symbol_size=10,
                 # orient="TB",
                 initial_tree_depth=3,
                 # label_opts=opts.LabelOpts(font_weight="bold", horizontal_align="center", vertical_align="center"),
                 tooltip_opts=opts.TooltipOpts(formatter="id: '{b}', isReal: {c}"),
                 itemstyle_opts=opts.ItemStyleOpts(color="orange"),
                 )
            .set_global_opts(title_opts=opts.TitleOpts(title="Tree-Nodes"))
    )
    return c


def csvToDict(file: str) -> dict:
    nodes_dict = {}
    csv = pd.read_csv(file, dtype=str)
    for node_id, father_id in csv.values:
        if father_id not in nodes_dict.keys():
            nodes_dict[father_id] = []
        nodes_dict[father_id].append(node_id)
    return nodes_dict


def dataBaseToDict(rolls: tuple) -> (dict, dict):
    """
    使用数据库中读取的条目构建父子关系字典
    :param rolls: 数据库中读取的条目，元组类型 (nodeid, parentid, nodeIsReal)
    :return: father_child_dict：父子关系字典，node_dict：虚实关系字典
    """
    father_child_dict = {}
    node_dict = {}
    for node_id, father_id, is_real in rolls:
        node_dict[node_id] = is_real
        if father_id not in father_child_dict.keys():
            father_child_dict[father_id] = []  # 这个list中存着所有的子节点
        father_child_dict[father_id].append(node_id)
    return father_child_dict, node_dict


def findRootsByDict(nodes_dict: dict) -> list:
    return nodes_dict[ROOT_STR]


def dataConstructor(root: str, node_dict: dict, is_real_dict: dict) -> Node:
    """
    根据根节点和父子关系字典生成树结构
    :param is_real_dict: 表示节点虚实的字典
    :param root: 根节点ID
    :param node_dict: 父子关系字典
    :return: 根节点Node
    """
    node_root = Node(root, [], is_real_dict[root])
    if root in node_dict.keys():
        for child in node_dict[root]:
            if child not in node_dict.keys():
                node_root.setChild(Node(child, [], is_real_dict[child]))
            else:
                node_root.setChild(dataConstructor(child, node_dict, is_real_dict))
    return node_root


def _dataFormatterHelp(root_node: Node):
    if root_node.getVal() == "01":
        _label = opts.LabelOpts(font_weight="bold", horizontal_align="center", vertical_align="center")
    else:
        _label = opts.LabelOpts(color="red", font_weight="bold", horizontal_align="center", vertical_align="center")
    res_dict = {"name": root_node.getName(), "value": root_node.getVal(), "label": _label,
                "children": [_dataFormatterHelp(child) for child in root_node.children]}
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
    relation_dict, isReal_dict = dataBaseToDict(DataBase("root", "m97z04l05").readDatabase())
    root_list = findRootsByDict(relation_dict)
    data_gen = []
    for root_str in root_list:
        root = dataConstructor(root_str, relation_dict, isReal_dict)
        res = dataFormatter(root)
        data_gen.append(res)
    tree = generateTree(data_gen)
    tree.add_js_funcs(
        '''
        chart_masterlovsky_tree_01.on('click',  function(param) {
        console.log(param)
        });  
        '''
    )
    print("structure:")
    print(json.dumps(tree.get_options().get("series")[0]["data"][0], indent=4, separators=(',', ':'),
                     cls=DateEncoding, ensure_ascii=False))
    tree.render("tree_Node.html")


if __name__ == '__main__':
    run()
