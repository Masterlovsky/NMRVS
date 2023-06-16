#! /usr/bin/python3
"""
By mzl 2021.06.23 version 1.0
Used to Analyze pcap files.
update to version 1.1 2023.06.16
"""

from queue import Queue

import yaml
try:
    import pandas as pd
    import matplotlib.pyplot as plt
    from pyecharts import options as opts
    from pyecharts.charts import Line, Bar, Page
    from pyecharts.globals import ThemeType
    from scapy.all import *
except ImportError as e:
    print("Install the required packages first.")
    try:
        command_to_execute = "pip install pandas || easy_install pandas" + \
                                " && pip install matplotlib || easy_install matplotlib" + \
                                " && pip install pyecharts || easy_install pyecharts" + \
                                " && pip install scapy || easy_install scapy"
        os.system(command_to_execute)
    except OSError:
        print("Can NOT install required lib, Aborted! Please install it manually.")
        sys.exit(1)
    import pandas as pd
    import matplotlib.pyplot as plt
    from pyecharts import options as opts
    from pyecharts.charts import Line, Bar, Page
    from pyecharts.globals import ThemeType
    from scapy.all import *


class ShowProcess(object):

    def __init__(self, max_steps, process_name="read pcap-file"):
        self.max_steps = max_steps  # Total number of times you need to process
        self.max_arrow = 50  # Length of the progress bar
        self.i = 0  # Current processing progress
        print(process_name + " start: ")

    # Effect is [>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>]100.00%
    def show_process(self, i=None):
        if i is not None:
            self.i = i
        num_arrow = int(self.i * self.max_arrow / self.max_steps)
        num_line = self.max_arrow - num_arrow
        percent = self.i * 100.0 / self.max_steps
        process_bar = '\r' + '[' + '>' * num_arrow + '-' * num_line + ']' + '%.2f' % percent + '%'
        sys.stdout.write(process_bar)
        sys.stdout.flush()
        self.i += 1

    def close(self, words='done'):
        print('')
        print(words)
        self.i = 1


def draw_dist_bar(delay_l: list, bins: int = 10):
    """
    draw delay distribution bar
    :param delay_l: delay list
    :param bins: number of bins
    :return: None
    """
    df = pd.DataFrame(delay_l, columns=["delay"], dtype="float")
    # get mean value, set time unit
    time_unit = "ms"
    unit = 1
    mean = df["delay"].mean()
    if mean < 10:
        time_unit = "us"
        unit = 1000
    # get hist list for df use cut
    hist_list = pd.cut(df["delay"] * unit, bins=bins, right=False, precision=0)
    # print(hist_list.value_counts(sort=False))
    page = Page(layout=Page.SimplePageLayout, page_title="Delay Distribution")
    # use pyecharts to draw hist bar
    hist = hist_list.value_counts(sort=False)
    line_dist = (
        Bar(init_opts=opts.InitOpts(width="960px", height="540px", theme=ThemeType.WHITE,
                                    page_title="DelayDistributionView",
                                    chart_id="masterlovsky_bar_01"))
        .add_xaxis(hist.index.astype(str).tolist())
        .add_yaxis("count", hist.values.tolist(), label_opts=opts.LabelOpts(is_show=False))
        .set_global_opts(title_opts=opts.TitleOpts(title="Delay Distribution"),
                         xaxis_opts=opts.AxisOpts(name="delay" + "(" + time_unit + ")",
                                                  name_textstyle_opts=opts.TextStyleOpts(font_size=14,
                                                                                         font_weight="bold")),
                         yaxis_opts=opts.AxisOpts(name="count"),
                         datazoom_opts=opts.DataZoomOpts(range_start=0, range_end=100, type_="inside"),
                         )
    )
    page.add(line_dist)

    # draw cdf line use pyecharts in the same html
    cdf = hist.cumsum() / hist.sum()
    x = hist.index.astype(str).tolist()
    x = ["0"] + [i.split(",")[1][1:-1] for i in x]
    y = [0] + cdf.values.tolist()
    line_cdf = (
        Line(init_opts=opts.InitOpts(width="960px", height="540px", theme=ThemeType.WHITE,
                                     page_title="DelayCDFView",
                                     chart_id="masterlovsky_line_02"))
        .add_xaxis(x)
        .add_yaxis("probability", y, is_step=True, label_opts=opts.LabelOpts(is_show=False),
                   linestyle_opts=opts.LineStyleOpts(width=2),
                   itemstyle_opts=opts.ItemStyleOpts(border_width=2))
        .set_global_opts(title_opts=opts.TitleOpts(title="Delay CDF"),
                         xaxis_opts=opts.AxisOpts(name="delay" + "(" + time_unit + ")",
                                                  name_textstyle_opts=opts.TextStyleOpts(font_size=14,
                                                                                         font_weight="bold")),
                         datazoom_opts=opts.DataZoomOpts(range_start=0, range_end=100, type_="inside"),
                         )
    )
    page.add(line_cdf)
    page.render("delay_dist.html")
    print("render delay_dist.html done!")


def draw_time_seq_line(delay_l: list, time_out: float):
    """
    draw a picture use packet delay list and timeout.
    :param delay_l: Unit: ms
    :param time_out: Unit: ms
    """
    if len(delay_l) == 1:
        print("Only one packet pair, skip drawing Picture process.")
        return
    unit = 1000  # use unit ms or us in the line chart (1000：us; 1: ms)
    if max(delay_l) > 10:
        unit = 1
    gap = int(len(delay_l) / xtick_num)
    gap = 1 if gap == 0 else gap  # choose interval gap between x ticks, default is 1
    x = [i for i in range(xtick_num)]
    y = [delay * unit for delay in delay_l[::gap]]
    if len(x) != len(y):
        y = y[:-1]  # 处理除不开的情况，删去最后一个y的值
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
                         yaxis_opts=opts.AxisOpts(name="Delay" + ("(us)" if unit == 1000 else "(ms)"), name_gap=45,
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
    print("render line_delay.html done!")


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
    if payload[:2] in ("71", "72", "0d", "0e"):
        return payload[8 + OFFSET:16 + OFFSET]
    elif payload[:2] in ("6f", "70", "73", "74", "0b", "0c", "0f", "10"):
        return payload[2:10]
    else:
        return None


def analyzeDelay(_delay_list: list, time_out: float):
    global send_req_total
    n = len(_delay_list)
    max_delay = max(_delay_list)
    min_delay = min(_delay_list)
    total = 0.0
    timeout_n = 0
    pbar = ShowProcess(n - 1, "pcap analyzing")
    for dl in _delay_list:
        pbar.show_process()
        total += dl
        if dl > time_out:
            timeout_n += 1
    pbar.close()
    average_delay = total / n
    print("min_delay: {:.3f}ms, max_delay: {:.3f}ms, average_delay: {:.4f}ms, timeout_n: {}"
          .format(min_delay, max_delay, average_delay, timeout_n))
    print("packet_pair_number:{}, packet_loss_rate: {:.2f}%".format(n, (1 - n / send_req_total) * 100))
    return average_delay


def analyzeDelayInfo(pkt: Packet):
    global processed_pkt_num
    global send_req_total
    processed_pkt_num += 1
    if processed_pkt_num % 5000 == 0:
        print("Already read {} packets...".format(processed_pkt_num))
    pkt_type = getPacketTypeFromPacket(pkt)
    requestID = getRequestIDFromPacket(pkt)
    if pkt_type is None or requestID is None:
        print("Warning, not a IRS standard packet, Pkt INFO: {}".format(pkt.summary()))
        return
    if pkt_type in ("6f", "71", "73", "0d", "0b", "0f"):
        pkt_pair_time_dict[requestID].put(pkt.time)
        send_req_total += 1
    # If it is a response message, pop the requestID and corresponding time stamp out and calculate time delay
    if pkt_type in ("70", "72", "74", "0e", "0c", "10"):
        if requestID in pkt_pair_time_dict.keys():
            delay = 1000 * (pkt.time - pkt_pair_time_dict.get(requestID).get())  # delay: ms
            if delay < 0:
                print("Warning, delay is less than 0, delay: {:.3f}ms, pkt info: {}".format(delay, pkt.summary()))
                return
            delay_list.append(delay)


def run():
    sniff(offline=sys.argv[1], prn=analyzeDelayInfo, store=0)
    if not delay_list:
        print("Error! delay_l is null, check your pcap file first.")
        exit(0)
    analyzeDelay(delay_list, timeout)


def argsCheck():
    offset = 2
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("use this script: python3 pktAnalyzer.py <test.pcap> or python3 pktAnalyzer.py <test.pcap> e/cc")
        exit(0)
    if len(sys.argv) == 3:
        if sys.argv[2] == "e":  # EID version
            offset = 0
        elif sys.argv[2] == "cc":  # cuckooFilter version
            offset = -6
        else:
            print("use this script: python3 pktAnalyzer.py <test.pcap> or python3 pktAnalyzer.py <test.pcap> e/cc")
            exit(0)
    return offset


if __name__ == '__main__':
    OFFSET = argsCheck()
    yml = readConf2Yml("conf.yml")
    timeout = yml["TIME_OUT"]
    xtick_num = yml["DRAW"]["XTICK_NUM"]
    dist_bins = yml["DRAW"]["DIST_BINS"]
    delay_list = []
    pkt_pair_time_dict = defaultdict(Queue)  # key: requestID； value: a queue of timestamp
    processed_pkt_num = 0
    send_req_total = 0
    run()
    draw_time_seq_line(delay_list, timeout)
    draw_dist_bar(delay_list, dist_bins)
