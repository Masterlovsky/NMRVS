#! /usr/bin/python3
"""
By mzl 2021.06.23 version 1.0
Used to Analyze pcap files.
"""

from queue import Queue

import yaml
from pyecharts import options as opts
from pyecharts.charts import Line
from pyecharts.globals import ThemeType
from scapy.all import *


def drawPicture(delay_l: list, time_out: float):
    """
    draw a picture use packet delay list and timeout.
    :param delay_l: 单位：ms
    :param time_out: 单位：ms
    """
    unit = 1000  # use unit ms or us in the line chart
    if max(delay_l) > 10:
        unit = 1
    gap = int(len(delay_l) / xtick_num)
    gap = 1 if gap == 0 else gap  # choose interval gap between x ticks, default is 1
    x = [i for i in range(int(len(delay_l) / gap))]
    y = [delay * unit for delay in delay_l[::gap]]
    y_max_idx = y.index(max(y))
    y_min_idx = y.index(min(y))
    c = (
        Line(init_opts=opts.InitOpts(width="1280px", height="720px", theme=ThemeType.WHITE,
                                     page_title="ResolveDelayView",
                                     chart_id="masterlovsky_line_01"))
            .add_xaxis(x)
            .add_yaxis("delay", y, symbol_size=10,
                       linestyle_opts=opts.LineStyleOpts(width=2),
                       itemstyle_opts=opts.ItemStyleOpts(border_width=2),
                       markline_opts=opts.MarkLineOpts(data=[opts.MarkLineItem(y=time_out * unit)]),
                       markpoint_opts=opts.MarkPointOpts(
                           data=[
                               opts.MarkPointItem(name="MAX", type_="max", symbol_size=70,
                                                  coord=[x[y_max_idx], y[y_max_idx]], value=y[y_max_idx]),
                               opts.MarkPointItem(name="MIN", type_="min", symbol_size=70,
                                                  coord=[x[y_min_idx], y[y_min_idx]], value=y[y_min_idx])
                           ]
                       )
                       )
            .set_global_opts(title_opts=opts.TitleOpts(title="DelayMeasure Line-Chart"),
                             xaxis_opts=opts.AxisOpts(type_="category",
                                                      name="packetIndex", name_gap=36, name_location="middle",
                                                      name_textstyle_opts=opts.TextStyleOpts(font_size=14,
                                                                                             font_weight="bold"),
                                                      boundary_gap=False,
                                                      axislabel_opts=opts.LabelOpts(margin=16, color="black"),
                                                      axistick_opts=opts.AxisTickOpts(
                                                          is_show=True, length=8,
                                                          linestyle_opts=opts.LineStyleOpts(color="grey"),
                                                      ),
                                                      splitline_opts=opts.SplitLineOpts(
                                                          is_show=True,
                                                          linestyle_opts=opts.LineStyleOpts(color="grey", opacity=0.4)
                                                      )),
                             yaxis_opts=opts.AxisOpts(name="Delay" + "(us)" if unit == 1000 else "(ms)", name_gap=45,
                                                      name_location="middle",
                                                      name_textstyle_opts=opts.TextStyleOpts(font_size=14,
                                                                                             font_weight="bold"),
                                                      boundary_gap=False,
                                                      axislabel_opts=opts.LabelOpts(margin=16, color="black"),
                                                      axistick_opts=opts.AxisTickOpts(
                                                          is_show=True, length=8,
                                                          linestyle_opts=opts.LineStyleOpts(color="grey"),
                                                      ),
                                                      splitline_opts=opts.SplitLineOpts(
                                                          is_show=True,
                                                          linestyle_opts=opts.LineStyleOpts(color="grey", opacity=0.4)
                                                      ))
                             )
            .render("line_delay.html")
    )
    print("render html done!")


def readConf2Yml(path: str):
    with open(path, 'r') as f:
        return yaml.load(f.read(), Loader=yaml.FullLoader)


def getPacketTypeFromPacket(pkt_item):
    """
    get requestID field from different kinds of resolve packets.
    :param pkt_item: packet item resolve from scapy
    :return: packetType
    """
    if pkt_item.haslayer("UDP"):
        payload = pkt_item["UDP"].payload.original.hex()
        return payload[:2]
    return None


def getRequestIDFromPacket(pkt_item):
    """
    get requestID field from different kinds of resolve packets.
    :param pkt_item: packet item resolve from scapy
    :return: String of requestID
    """
    if pkt_item.haslayer("UDP"):
        payload = pkt_item["UDP"].payload.original.hex()
        return getRequestID(payload)
    return None


def getRequestID(payload: str):
    if payload[:2] == "71" or payload[:2] == "72":
        return payload[8:16]
    elif payload[:2] in ("6f", "70", "73", "74"):
        return payload[2:10]
    else:
        return None


def analyzeDelay(delay_list: list, time_out: float):
    n = len(delay_list)
    max_delay = max(delay_list)
    min_delay = min(delay_list)
    total = 0.0
    timeout_n = 0
    for dl in delay_list:
        total += dl
        if dl > time_out:
            timeout_n += 1
    average_delay = total / n
    print("packet-pair number: {}, min_delay: {:.3f}ms, max_delay: {:.3f}ms, average_delay: {:.4f}ms, timeout_n: {}"
          .format(n, min_delay, max_delay, average_delay, timeout_n))
    return average_delay


def run():
    packets = rdpcap(sys.argv[1])
    pkt_pair_time_dict = defaultdict(Queue)  # key: requestID； value: a queue of timestamp
    delay_l = []  # store each delay value of packet-pair
    for pkt in packets:
        pkt_type = getPacketTypeFromPacket(pkt)
        requestID = getRequestIDFromPacket(pkt)
        # If it is a request packet, put requestID and corresponding timestamp into the dictionary
        if pkt_type in ("6f", "71", "73"):
            if requestID is not None:
                pkt_pair_time_dict[requestID].put(pkt.time)
        # If it is a response message, pop the requestID and corresponding time stamp out and calculate time delay
        if pkt_type in ("70", "72", "74"):
            if requestID is not None:
                delay = 1000 * (pkt.time - pkt_pair_time_dict.get(requestID).get())  # delay: ms
                delay_l.append(delay)
    analyzeDelay(delay_l, timeout)
    return delay_l, timeout


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("use this script: python3 pktAnalyzer.py <test.pcap>")
        exit(0)
    yml = readConf2Yml("conf.yml")
    timeout = yml["TIME_OUT"]
    xtick_num = yml["DRAW"]["XTICK_NUM"]
    _delay_list, _time_out = run()
    drawPicture(_delay_list, _time_out)
