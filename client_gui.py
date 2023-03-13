#! /usr/bin/python3
# -*- coding: utf-8 -*-
"""
This script runs client GUI for NRS. Automatically call client.py execute.
The front page is displayed at localhost:8082 in the browser.
powered by masterlovsky. 2023/03/13
"""
import os
import subprocess
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


def execute(cmd, desc=""):
    put_markdown("### 测试结果-{}".format(desc))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    for line in iter(p.stdout.readline, b''):
        put_text(line.decode().rstrip())


def fast_check(_ip, _port):
    def fast_run():
        cmd = "python3 client.py -i {} -p {} -c rcid".format(_ip, _port)
        execute(cmd, "注册")
        cmd = "python3 client.py -i {} -p {} -c ecid".format(_ip, _port)
        execute(cmd, "解析")
        cmd = "python3 client.py -i {} -p {} -c dcid".format(_ip, _port)
        execute(cmd, "注销")
        cmd = "python3 client.py -i {} -p {} -c ecid".format(_ip, _port)
        execute(cmd, "解析2")
        put_success("快速测试完成")

    put_markdown("## 快速测试")
    put_markdown("- 快速测试用于检测解析节点是否正常工作，不需要输入任何参数，脚本以默认参数执行。")
    put_button("run", onclick=fast_run, color="success")


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
            checkbox("", name="extra", options=["开启扩展"]),
        ])
        if len(data["eid"]) != 40 or len(data["cid"]) != 64 or len(data["na"]) != 32:
            put_markdown("### 参数错误，请检查输入")
            return
        data_ex = None
        if data["extra"] == ["开启扩展"]:
            # add new input_group to config number and speed
            data_ex = input_group("扩展选项", [
                checkbox("", name="force", options=["性能模式", "随机reqID"], value=["性能模式", "随机reqID"],
                         inline=True),
                checkbox("sequence-mode", name="sequence", options=["序列EID", "序列CID", "随机Tag"],
                         value=[], inline=True),
                input('number', name='number', type=NUMBER, placeholder="1", value="1"),
                input('speed', name='speed', type=NUMBER, placeholder="-1(not limited)", value="-1"),
                input('burst_size', name='burst', type=NUMBER, placeholder="2000", value="2000"),
            ])
        cmd_str = data["eid"] + data["cid"] + data["na"] + " " + data["tlv"] + (" g" if global_flag else "")
        cmd = "python3 client.py -i {} -p {} -ecr {}".format(_ip, _port, cmd_str)
        if data_ex:
            if "性能模式" in data_ex["force"]:
                cmd += " --force"
            if "随机reqID" in data_ex["force"]:
                cmd += " --ranReqID"
            if "序列EID" in data_ex["sequence"]:
                cmd += " --seq"
            if "序列CID" in data_ex["sequence"]:
                cmd += " --seqc"
            if "随机Tag" in data_ex["sequence"]:
                cmd += " --seqT"
            cmd += " -n {}".format(data_ex["number"])
            cmd += " -s {}".format(data_ex["speed"])
            cmd += " -b {}".format(data_ex["burst"])
            if data_ex["number"] == 1:
                cmd += " -d"
        else:
            cmd += " -d"
        put_markdown("Generate command: \n ```shell \n {} \n ``` \n".format(cmd))
        put_button("run", onclick=partial(execute, cmd), color="success")

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
            checkbox("", name="extra", options=["开启扩展"]),
        ])
        if ((data["type"] == "eid->ip" or data["type"] == "eid->cid") and len(data["eid"]) != 40) or (
                (data["type"] == "cid->ip" or data["type"] == "cid->eid") and len(data["cid"]) != 64):
            put_markdown("### 参数错误，请检查输入")
            return
        data_ex = None
        if data["extra"] == ["开启扩展"]:
            # add new input_group to config number and speed
            data_ex = input_group("扩展选项", [
                checkbox("", name="force", options=["性能模式", "随机reqID"], value=["性能模式", "随机reqID"],
                         inline=True),
                input('number', name='number', type=NUMBER, placeholder="1", value="1"),
                input('speed', name='speed', type=NUMBER, placeholder="-1(not limited)", value="-1"),
                input('burst_size', name='burst', type=NUMBER, placeholder="2000", value="2000"),
            ])
        type_map = {"eid->ip": "0", "eid->cid": "1", "cid->ip": "2", "ecid->ip": "3", "tag->all": "4", "cid->eid": "5"}
        cmd_str = type_map[data["type"]] + " " + data["eid"] + data["cid"] + data["na"] + (" g" if global_flag else "")
        cmd = "python3 client.py -i {} -p {} -ecq {}".format(_ip, _port, cmd_str)
        if data_ex:
            if "性能模式" in data_ex["force"]:
                cmd += " --force"
            if "随机reqID" in data_ex["force"]:
                cmd += " --ranReqID"
            cmd += " -n {}".format(data_ex["number"])
            cmd += " -s {}".format(data_ex["speed"])
            cmd += " -b {}".format(data_ex["burst"])
            if data_ex["number"] == 1:
                cmd += " -d"
        else:
            cmd += " -d"
        put_markdown("Generate command: \n ```shell \n {} \n ``` \n".format(cmd))
        put_button("run", onclick=partial(execute, cmd), color="success")

    def deregister():
        data = input_group("参数设置", [
            input('EID', name='eid', type=TEXT, required=True, placeholder="b" * 40, value="b" * 40,
                  help_text="hex string in 40"),
            input('CID', name='cid', type=TEXT, required=True, placeholder="0" * 64, value="0" * 64,
                  help_text="hex string in 64"),
            input('NA', name='na', type=TEXT, required=True, placeholder="0" * 32, value="0" * 32,
                  help_text="hex string in 32"),
            checkbox("", name="extra", options=["开启扩展"]),
        ])
        if len(data["eid"]) != 40 or len(data["cid"]) != 64 or len(data["na"]) != 32:
            put_markdown("### 参数错误，请检查输入")
            return
        data_ex = None
        if data["extra"] == ["开启扩展"]:
            # add new input_group to config number and speed
            data_ex = input_group("扩展选项", [
                checkbox("", name="force", options=["性能模式", "随机reqID"], value=["性能模式", "随机reqID"],
                         inline=True),
                input('number', name='number', type=NUMBER, placeholder="1", value="1"),
                input('speed', name='speed', type=NUMBER, placeholder="-1(not limited)", value="-1"),
                input('burst_size', name='burst', type=NUMBER, placeholder="2000", value="2000"),
            ])
        cmd_str = data["eid"] + data["cid"] + data["na"] + (" g" if global_flag else "")
        cmd = "python3 client.py -i {} -p {} -ecd {}".format(_ip, _port, cmd_str)
        if data_ex:
            if "性能模式" in data_ex["force"]:
                cmd += " --force"
            if "随机reqID" in data_ex["force"]:
                cmd += " --ranReqID"
            cmd += " -n {}".format(data_ex["number"])
            cmd += " -s {}".format(data_ex["speed"])
            cmd += " -b {}".format(data_ex["burst"])
            if data_ex["number"] == 1:
                cmd += " -d"
        else:
            cmd += " -d"
        put_markdown("Generate command: \n ```shell \n {} \n ``` \n".format(cmd))
        put_button("run", onclick=partial(execute, cmd), color="success")

    def custom():
        data = input_group("自定义报文", [
            textarea('msg', name='msg', required=True, placeholder="hex string payload",
                     help_text="send a raw udp packet with message"),
            checkbox("", name="extra", options=["开启扩展"]),
        ])
        cmd = "python3 client.py -i {} -p {} -m {} -d".format(_ip, _port, data["msg"])
        put_markdown("Generate command: \n ```shell \n {} \n ``` \n".format(cmd))
        put_button("run", onclick=partial(execute, cmd), color="success")

    global_flag = True if _port == '10090' else False
    put_buttons(['注册', '解析', '注销', '自定义'], onclick=[register, resolve, deregister, custom], group=True)


def advanced_check(_ip, _port):
    put_markdown("### 待开发...")


def get_ip_port():
    data = input_group("请输入解析节点IP地址和端口号", [
        input('IP', name='ip', type=TEXT, required=True),
        select('port', name='port', options=["level1-10061", "level2-10062", "level3-10063", "global-10090"],
               value="level1-10061", required=True),
    ])
    # s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    put_markdown("**Server-IP**: {}，**port**: {}".format(data['ip'], data['port'].split('-')[1]))
    return data['ip'], data['port'].split('-')[1]


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
    start_server(main, port=8082, auto_open_webbrowser=True)
