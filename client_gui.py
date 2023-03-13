#! /usr/bin/python3
# -*- coding: utf-8 -*-
"""
This script runs client GUI for NRS. Automatically call client.py execute.
The front page is displayed at localhost:8082 in the browser.
"""
import os
import sys
import socket
import time
from functools import partial

try:
    import pywebio
except ImportError:
    try:
        command_to_execute = "pip install pywebio -i https://pypi.tuna.tsinghua.edu.cn/simple || easy_install pywebio"
        os.system(command_to_execute)
    except OSError:
        print("Can NOT install pywebio, Aborted!")
        sys.exit(1)

from pywebio import *
from pywebio.input import *
from pywebio.output import *


def get_time():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def fast_check(_ip, _port):
    put_markdown("## 快速测试")
    put_markdown("- 快速测试用于检测解析节点是否正常工作，不需要输入任何参数，脚本以默认参数执行。")
    cmd = "python3 client.py -i {} -p {} -c rcid".format(_ip, _port)
    res = os.popen(cmd).read()
    put_markdown("### 测试结果-注册")
    put_text(res)
    cmd = "python3 client.py -i {} -p {} -c ecid".format(_ip, _port)
    res = os.popen(cmd).read()
    put_markdown("### 测试结果-解析")
    put_text(res)
    cmd = "python3 client.py -i {} -p {} -c dcid".format(_ip, _port)
    res = os.popen(cmd).read()
    put_markdown("### 测试结果-注销")
    put_text(res)
    cmd = "python3 client.py -i {} -p {} -c ecid".format(_ip, _port)
    res = os.popen(cmd).read()
    put_markdown("### 测试结果-解析")
    put_text(res)
    put_success("快速测试完成")


def normal_check(_ip, _port):
    def register():
        data = input_group("参数设置", [
            input('EID', name='eid', type=TEXT, required=True, placeholder="b" * 40, value="b" * 40,
                  help_text="hex string in 40"),
            input('CID', name='cid', type=TEXT, required=True, placeholder="0" * 64, value="0" * 64,
                  help_text="hex string in 64"),
            input('NA', name='na', type=TEXT, required=True, placeholder="0" * 32, value="0" * 32,
                  help_text="hex string in 32"),
            input('TLV', name='tlv', type=TEXT, placeholder="010101 for Tag1 of value{1}"),

        ])
        if len(data["eid"]) != 40 or len(data["cid"]) != 64 or len(data["na"]) != 32:
            put_markdown("### 参数错误，请检查输入")
            return
        cmd_str = data["eid"] + data["cid"] + data["na"] + " " + data["tlv"] + (" g" if global_flag else "")
        cmd = "python3 client.py -i {} -p {} -ecr {} -d".format(_ip, _port, cmd_str)
        put_markdown("Generate command: \n ```shell \n {} \n ``` \n".format(cmd))
        res = os.popen(cmd).read()
        put_markdown("### 测试结果:")
        put_text(res)

    def resolve():
        data = input_group("参数设置", [
            radio('解析类型', options=['eid->ip', 'eid->cid', 'cid->ip', 'ecid->ip', 'tag->all', 'cid->eid'],
                  name='type', inline=True, required=True, value='eid->ip'),
            input('EID', name='eid', type=TEXT, placeholder="(optional)",
                  help_text="hex string in 40"),
            input('CID', name='cid', type=TEXT, placeholder="(optional)",
                  help_text="hex string in 64"),
            input('NA', name='na', type=TEXT, placeholder="(optional)",
                  help_text="hex string in 32"),
        ])
        if ((data["type"] == "eid->ip" or data["type"] == "eid->cid") and len(data["eid"]) != 40) or (
                (data["type"] == "cid->ip" or data["type"] == "cid->eid") and len(data["cid"]) != 64):
            put_markdown("### 参数错误，请检查输入")
            return
        type_map = {"eid->ip": "0", "eid->cid": "1", "cid->ip": "2", "ecid->ip": "3", "tag->all": "4", "cid->eid": "5"}
        cmd_str = type_map[data["type"]] + " " + data["eid"] + data["cid"] + data["na"] + (" g" if global_flag else "")
        cmd = "python3 client.py -i {} -p {} -ecq {} -d".format(_ip, _port, cmd_str)
        put_markdown("Generate command: \n ```shell \n {} \n ``` \n".format(cmd))
        res = os.popen(cmd).read()
        put_markdown("### 测试结果:")
        put_text(res)

    def deregister():
        data = input_group("参数设置", [
            input('EID', name='eid', type=TEXT, required=True, placeholder="b" * 40, value="b" * 40,
                  help_text="hex string in 40"),
            input('CID', name='cid', type=TEXT, required=True, placeholder="0" * 64, value="0" * 64,
                  help_text="hex string in 64"),
            input('NA', name='na', type=TEXT, required=True, placeholder="0" * 32, value="0" * 32,
                  help_text="hex string in 32"),
        ])
        if len(data["eid"]) != 40 or len(data["cid"]) != 64 or len(data["na"]) != 32:
            put_markdown("### 参数错误，请检查输入")
            return
        cmd_str = data["eid"] + data["cid"] + data["na"] + (" g" if global_flag else "")
        cmd = "python3 client.py -i {} -p {} -ecd {} -d".format(_ip, _port, cmd_str)
        put_markdown("Generate command: \n ```shell \n {} \n ``` \n".format(cmd))
        res = os.popen(cmd).read()
        put_markdown("### 测试结果:")
        put_text(res)

    def custom():
        data = input_group("自定义报文", [
            textarea('msg', name='msg', required=True, placeholder="hex string payload",
                     help_text="send a raw udp packet with message"),
        ])
        cmd = "python3 client.py -i {} -p {} -m {} -d".format(_ip, _port, data["msg"])
        put_markdown("Generate command: \n ```shell \n {} \n ``` \n".format(cmd))
        res = os.popen(cmd).read()
        put_markdown("### 测试结果:")
        put_text(res)

    global_flag = True if _port == '10090' else False
    put_buttons(['注册', '解析', '注销', '自定义'], onclick=[register, resolve, deregister, custom], group=True)


def advanced_check(_ip, _port):
    put_markdown("### 待开发...")


def get_ip_port():
    data = input_group("请输入解析节点IP地址和端口号", [
        input('IP', name='ip', type=TEXT, required=True),
        input('端口号', name='port', type=NUMBER, required=True, value='10061',
              help_text="level1-10061, level2-10062, level3-10063, global-10090"),
    ])
    # s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    put_markdown("**Server-IP**: {}，**port**: {}".format(data['ip'], data['port']))
    return data['ip'], data['port']


def check_client():
    # check if client.py exists
    if not os.path.exists("client.py"):
        put_markdown("## 未检测到client.py，请将client.py放在当前目录下")
        exit(0)


def main():
    put_markdown("# NRS-client-GUI")
    check_client()
    version = os.popen("python3 client.py -v").read()
    put_markdown("> client version: {}".format(version))
    put_markdown("**Date**: {} | **ClientIP**: {}".format(get_time(), socket.gethostbyname(socket.gethostname())))
    ip, port = get_ip_port()
    put_buttons(['快速测试', '普通测试', '高级测试'],
                onclick=[partial(fast_check, ip, port), partial(normal_check, ip, port),
                         partial(advanced_check, ip, port)])


if __name__ == '__main__':
    start_server(main, port=8082, auto_open_webbrowser=False)
