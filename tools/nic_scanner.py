#! /usr/bin/python3
"""
This script is used to get the local interface name by destination IP address.
Version.  2023-01-31

example:
    python3 nic_scanner.py
    input the destination: www.baidu.com/192.168.100.1/2400:dd01::1, etc.
    You will get the local interface name like: enp0s25/em1/eth0.
    Additionally, you can get the MAC address of the interface.

"""
import os
import sys
import socket

try:
    import netifaces
except ImportError:
    try:
        command_to_execute = "pip install netifaces -i https://pypi.tuna.tsinghua.edu.cn/simple || easy_install netifaces"
        os.system(command_to_execute)
    except OSError:
        print("Can NOT install netifaces, Aborted!")
        sys.exit(1)
    import netifaces


def get_local_ip(destination_ip):
    # if destination_ip is ipv4, use socket.SOCK_DGRAM
    if destination_ip.count('.') == 3:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((destination_ip, 80))
            return s.getsockname()[0]
    # if destination_ip is ipv6, use socket.SOCK_DGRAM
    elif destination_ip.count(':') >= 2:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.connect((destination_ip, 80))
            return s.getsockname()[0]
    else:
        print("Invalid IP address, Aborted!")
        sys.exit(1)


# get source IP address by url
def get_ip_address(destination):
    try:
        destination_ip = socket.gethostbyname(destination)
    except socket.gaierror:
        destination_ip = destination
    return destination_ip


def get_local_interface(ipaddr):
    for interface in netifaces.interfaces():
        # get correct interface by ipaddr
        ifconfig = netifaces.ifaddresses(interface)
        # print(ifconfig)
        if netifaces.AF_INET in ifconfig and ipaddr == ifconfig[netifaces.AF_INET][0]['addr']:
            return interface
        if netifaces.AF_INET6 in ifconfig and ipaddr == ifconfig[netifaces.AF_INET6][0]['addr']:
            return interface
    return None


def get_mac_address(nic_name):
    ifconfig = netifaces.ifaddresses(nic_name)
    return ifconfig[netifaces.AF_LINK][0]['addr']


if __name__ == "__main__":
    destination = input("Please input the destination: ")
    dip = get_ip_address(destination)
    sip = get_local_ip(dip)
    nic_name = get_local_interface(sip)
    nic_mac = get_mac_address(nic_name)
    print("Local Interface for %s (%s -> %s): %s (MAC: %s)" % (dip, sip, dip, nic_name, nic_mac))
