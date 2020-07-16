#!/usr/bin/env python3

# ----------------------------------------------------------------------------------------------------------------------
# Copyright 2020 (c) Dr Warren Creemers
# See LICENSE in root folder for further information.
# ----------------------------------------------------------------------------------------------------------------------

import argparse
import ipaddress
import math
import socket
import subprocess
import time
import ray
from asciimatics.screen import Screen
from getmac import get_mac_address
import csv
import os
from typing import NamedTuple


# ----------------------------------------------------------------------------------------------------------------------
# Caches that are filled slowly
# ----------------------------------------------------------------------------------------------------------------------
port_scan_res = {}
mac_scan_res = {}

# ----------------------------------------------------------------------------------------------------------------------
# UI Config
# ----------------------------------------------------------------------------------------------------------------------
COLOUR_BLACK = 0
COLOUR_RED = 1
COLOUR_GREEN = 2
COLOUR_YELLOW = 3
COLOUR_BLUE = 4
COLOUR_MAGENTA = 5
COLOUR_CYAN = 6
COLOUR_WHITE = 7
A_BOLD = 1
A_NORMAL = 2
A_REVERSE = 3
A_UNDERLINE = 4


# ----------------------------------------------------------------------------------------------------------------------
# Ping statistics
# ----------------------------------------------------------------------------------------------------------------------
class PingStats:
    """
    A running stats class for: count(n), mean, sum and variance.
    """
    def __init__(self):
        self.n: int = 0
        self.mean: float = 0.0
        self.variance: float = 0.0
        self.sum: float = 0.0
        self.min: float = None
        self.max: float = None
        self.fails: int = 0
        self.last_fail = -1
        self.last_ok = -1
        self.last_ping = -1

    def __str__(self):
        return f"m(S)={int(self.mean)} ({int(self.sd_sample())}) b={int(self.min)} w={int(self.max)}"

    def clear(self):
        self.n = 0
        self.mean = 0.0
        self.variance = 0.0
        self.sum = 0.0
        self.min = None
        self.max = None

    def sd_population(self):
        """
        Classical standard deviation.
        """
        return math.sqrt(self.variance / self.n) if self.n > 0 else 0.0

    def sd_sample(self):
        """
        Sample standard deviation.
        """
        return math.sqrt(self.variance / (self.n - 1)) if self.n > 1 else 0.0

    def percent_reachable(self):
        """
        Basically percent uptime
        """
        n_including_fails = self.n + self.fails
        return 1.0 - (self.fails / n_including_fails) if self.n > 0 else 0.0

    def add(self, ping: int):
        """
        Add another value from the data set and update the stats.
        """
        self.last_ping = ping
        if ping < 0:
            self.fails += 1
            self.last_fail = time.time()
            return

        self.last_ok = time.time()
        value = float(ping)
        self.n += 1
        self.sum += value
        m_prev = self.mean
        self.mean += (value - self.mean) / self.n
        self.variance += (value - self.mean) * (value - m_prev)

        if self.n == 1:
            self.min = self.max = value
        else:
            self.min = min(self.min, value)
            self.max = max(self.max, value)


# ----------------------------------------------------------------------------------------------------------------------
# Ping code
# ----------------------------------------------------------------------------------------------------------------------
@ray.remote
def r_ping(ip: str, time_out: int = 20):
    """
    parallel ping
    """
    return sys_ping(ip, time_out)

@ray.remote
def r_port_ping(ip: str, port: int, time_out: int = 20):
    """
    parallel ping
    """
    return ping(ip, port, time_out)


def sys_ping(ip: str, time_out: int = 20):
    """
    Ping via sys command.
    """
    cmd = ['ping', '-c', '1', '-W', str(time_out), str(ip)]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = str(res.stdout, 'utf-8')
    err = str(res.stderr, 'utf-8')

    if res.returncode != 0:
        return -1

    if (err is not None) and len(err) > 0:
        # On my distro ping stuffs around dumping hints to stderr for these addresses.
        if ip not in ['192.168.0.0', '192.168.0.255']:
            return -2

    if 'destination host unreachable' in output.lower():
        return -3

    else:
        time_tokens = [t for t in output.split(' ') if t.lower().startswith('time=')]
        ms = float(time_tokens[0].split('=')[1])
        return int(ms*1000)


def ping(ip: str, port: int = 22, time_out: int = 20):
    """
    Failed attempt at a decent native ping, that did not require root.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        s.settimeout(time_out)
        time.sleep(1)
        start = time.clock()
        s.connect((ip, port))
        s.shutdown(socket.SHUT_RDWR)
        duration = time.clock()-start
        s.close()
        return int(duration*1000000)

    except OSError:
        return -1


def scan_network(ip_range: ipaddress.IPv4Network, time_out: int = 6):
    addresses = [str(ip) for ip in ipaddress.IPv4Network(ip_range)]
    return scan(addresses, time_out=time_out)


def scan(addresses, time_out: int = 1):
    futures = [r_ping.remote(ip, time_out=time_out) for ip in addresses]
    res = [(ip, ns) for ip, ns in zip(addresses, ray.get(futures)) if ns >= 0]
    return res


def update_ping_stats(ping_stats, ping_results) -> bool:
    """
    :param ping_stats: Dictionary of ping statistics
    :param ping_results:  Result of last scan
    """
    new_ips = False
    for ip, ping in ping_results:
        if not ip in ping_stats:
            new_ips = True
            ping_stats[ip] = PingStats()

    # update the dictionary
    ping_dict = {ip: ping for ip, ping in ping_results}
    for ip, stats in ping_stats.items():
        if ip in ping_dict:
            stats.add(ping_dict[ip])
        else:
            stats.add(-1)
    return new_ips


# ----------------------------------------------------------------------------------------------------------------------
# Port Scan
# ----------------------------------------------------------------------------------------------------------------------
tcp_ports_we_care_about = {
        9: 'WoL',          20: 'FTP',          22: 'SSH',          23: 'Telnet',       25: 'SMTP',
       53: 'DNS',          80: 'HTTP',        110: 'POP3',        119: 'NNTP',        123: 'NTP',
      135: 'EPMAP',       137: 'NetBIOS',     143: 'IMAP',        161: 'SNMP',        177: 'XDMCP',
      194: 'IRC',         213: 'IPX',         220: 'IMAPv3',      443: 'HTTPS',       389: 'LDAP',
      554: 'RTSP',       1119: 'BattleNET',  1220: 'QTSS',       1234: 'VLC',        1433: 'MSSQL',
     1755: 'MMS',        1935: 'RTMP',       2399: 'JDBC',       3306: 'MySQL',      3389: 'RDP',
     5000: 'UPnP',       5432: 'Postgre',    5938: 'TeamViewer', 2375: 'Docker',     2376: 'DockerSSL',
     2377: 'DockerSwrm', 4070: 'Alexa',      5984: 'CouchDB',    6000: 'X11',        7070: 'RTSP',
     8200: 'GoToMyPC',   9001: 'HSQLDB ',    9150: 'Tor',        9418: 'git',       27036: 'Steam-Stream',
    32400: 'Plex',      32764: 'Router-Backdoor'
}

udp_ports_we_care_about = {
    1900: 'Bonjour'
}


def quick_port_scan(ip: str):
    # parallel version, cause waiting for 40+ timeouts would take a while in sequence
    ports = [p for p in tcp_ports_we_care_about.keys()]
    futures = [r_port_ping.remote(ip, p, time_out=2) for p in ports]
    res = [p for p, ns in zip(ports, ray.get(futures)) if ns >= 0]

    # for port in tcp_ports_we_care_about.keys():
    #     if ping(ip, port, 1) > 0:
    #         res.append(port)
    #         # TODO handle UPD scan
    return res


# ----------------------------------------------------------------------------------------------------------------------
# MAC address
# ----------------------------------------------------------------------------------------------------------------------
def mac_scan(ip: str):
    # TODO: use data from https://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries
    try:
        mac = get_mac_address(ip=ip, network_request=True)
        return str(mac).upper().strip()
    except Exception:
        return "error"


class MACInfo(NamedTuple):
    oui: str
    country: str
    company: str


mac_info_lut = {}


def load_manufacturer_info():
    import re

    def sentence_case(s):
        return "".join([c.lower() if i != 0 else c for i, c in enumerate(s)])

    # open local version of http://standards-oui.ieee.org/oui/oui.csv
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'oui.csv')) as f:
        # sanitise the file
        legal_tla_regex = r'[^\w](s,r,o|s,r,l|s,l|r,o|s,a|d,o,o|o,o|pte|S,p,A|b,v|a,s|d,d|de[^\w]France|a .* Comp.*)[^\w]'
        legal_tla_regex = legal_tla_regex.replace(',', r'[\\\,\.\/\;]')
        legal_tla_regex = re.compile(legal_tla_regex, flags=re.IGNORECASE)

        legal_nonsense_regex = r"[^\w](ltd|co|ltd|llc|inc|corp|group|pos|pvt|pte|aps|sa|PLC|pty|AB|ans|int|Corporate|" \
                               r"GmbH|KG|ASA|AG|corporation|MFG|oy|dd|Limited|Sdn|Bhd|PUB|SYS|DIV|s|p|dd|y|BV)[^\w]"
        legal_nonsense_regex = re.compile(legal_nonsense_regex, flags=re.IGNORECASE)

        csv_reader = csv.reader(f, delimiter=',', quotechar='"')
        header = True
        for row in csv_reader:
            if header:
                header = False
            else:
                oui = row[1].strip()
                company = row[2] + ' '  # helps the regex match things at the end

                # remove complex legal shit
                company = legal_tla_regex.sub(' ', company)

                # remove simple legal shit
                company = re.sub(r'[^\w\-]', '   ', company)  # extra padding to stop chained legal stuff defeting the regex eg: "pty,ltd"
                company = legal_nonsense_regex.sub(' ', company)

                # Convert long words to sentence case
                company = [w.strip() for w in company.split(' ')]
                company = [w if len(w) <= 4 else sentence_case(w) for w in company]
                company = [w for w in company if len(w) > 0]
                company = " ".join(company)

                # extract country
                country = row[3]
                country = country.replace(",", ' ').replace(".", ' ').replace(";", ' ').split(' ')
                country = [x for x in country if len(x) == 2]
                if len(country) == 0:
                    country = '?'
                else:
                    country = country[-1]

                m = MACInfo(oui, country, company)
                mac_info_lut[oui] = m


# ----------------------------------------------------------------------------------------------------------------------
# GUI Code
# ----------------------------------------------------------------------------------------------------------------------
def ping_ns_to_ms(ping_ns: int) -> str:
    if ping_ns < 0:
        if ping == -2:
            return "(err)"
        elif ping == -2:
            return "(n/h)"
        else:
            return "(n/a)"
    if ping_ns > 1000:
        return str(int(round(ping_ns/1000)))
    else:
        return f"{(ping_ns/1000):.3f}"


def get_ping_colour(ping) -> str:
    ping_col = COLOUR_GREEN
    if ping > 5000:
        ping_col = COLOUR_RED
    elif ping > 1000:
        ping_col = COLOUR_YELLOW
    elif ping > 100:
        ping_col = COLOUR_CYAN
    elif ping < 0:
        ping_col = COLOUR_MAGENTA
    return ping_col


def time_since_as_str(when):
    if when == -1:
        return "n/a"  # no event recorded yet

    seconds = time.time() - when
    seconds = int(seconds)

    mins = (seconds // 60) % 60
    hrs = (mins // 60) % 24
    days = hrs // 24
    secs = seconds % 60

    if seconds < 60:
        return f"{secs}s"
    if seconds < 60*60:
        return f"{mins}m:{secs}"
    if seconds < 24*60*60:
        return f"{hrs}h:{mins}"
    else:
        return f"{days}d:{hrs}"


class ColConfig:
    def __init__(self, pirority, heading, width, print_func):
        self.pirority = pirority
        self.heading = heading
        self.width = width
        self.print_func = print_func


def format_flag(col_width: int, ip: str, stats: PingStats, ping: int):
    return ' '.ljust(col_width), COLOUR_RED, COLOUR_BLACK, A_BOLD


def format_ip(col_width: int, ip: str, stats: PingStats, ping: int):
    txt = ip.ljust(col_width)
    return txt, COLOUR_WHITE, COLOUR_BLACK, A_BOLD


def format_ping(col_width: int, ip: str, stats: PingStats, ping: int):
    txt = ping_ns_to_ms(ping).rjust(col_width)
    return txt, get_ping_colour(ping), COLOUR_BLACK, A_BOLD


def format_mean(col_width: int, ip: str, stats: PingStats, ping: int):
    t, f, b, _ = format_ping(col_width, ip, stats, stats.mean)
    return t, f, b, A_NORMAL


def format_best(col_width: int, ip: str, stats: PingStats, ping: int):
    t, f, b, _ = format_ping(col_width, ip, stats, stats.min)
    return t, f, b, A_NORMAL


def format_worst(col_width: int, ip: str, stats: PingStats, ping: int):
    t, f, b, _ = format_ping(col_width, ip, stats, stats.max)
    return t, f, b, A_NORMAL


def format_sd(col_width: int, ip: str, stats: PingStats, ping: int):
    txt = f" {ping_ns_to_ms(stats.sd_sample())}".ljust(col_width)
    return txt, COLOUR_WHITE, COLOUR_BLACK, A_NORMAL


def format_up_time(col_width: int, ip: str, stats: PingStats, ping: int):
    color = COLOUR_WHITE
    up = stats.percent_reachable()
    txt = f"{(up * 100):.2f}%".rjust(col_width)
    if txt.strip().startswith("100"):
        txt = "100%".rjust(col_width)
        color = COLOUR_GREEN
    return txt, color, COLOUR_BLACK, A_NORMAL


def format_last_outage(col_width: int, ip: str, stats: PingStats, ping: int):
    color = COLOUR_WHITE
    if stats.last_fail == -1:
        if stats.last_ok == -1:
            txt = '-'
        else:
            txt = "-"  # time_since_as_str(stats.last_fail)
            color = COLOUR_GREEN
    else:
        if (stats.last_ok == -1) or stats.last_ok < stats.last_fail:
            txt = f"-{time_since_as_str(stats.last_ok)}"
            color = COLOUR_RED
        else:
            txt = time_since_as_str(stats.last_fail)
            color = COLOUR_CYAN

    txt = (' ' + txt).ljust(col_width)
    return txt, color, COLOUR_BLACK, A_NORMAL


def format_name(col_width: int, ip: str, stats: PingStats, ping: int):
    try:
        txt = ' ' + socket.gethostbyaddr(ip)[0].strip()
        txt = txt.ljust(col_width)[:col_width]
        return txt, COLOUR_WHITE, COLOUR_BLACK, A_NORMAL
    except socket.herror:
        return " (unknown)", COLOUR_RED, COLOUR_BLACK, A_NORMAL


def format_services(col_width: int, ip: str, stats: PingStats, ping: int):
    if ip in port_scan_res:
        ports = port_scan_res[ip]
        txt = ",".join([tcp_ports_we_care_about[p] for p in ports])
        if len(txt) > col_width:
            # redo with marquee effect
            seconds = int(time.time())
            ports = [ports[(i + seconds) % len(ports)] for i in range(len(ports))]
            txt = ",".join([tcp_ports_we_care_about[p] for p in ports])
            txt = txt[:col_width]
        else:
            txt = txt.ljust(col_width)

        return txt, COLOUR_BLACK, COLOUR_CYAN, A_NORMAL
    return 'scanning'.ljust(col_width), COLOUR_MAGENTA, COLOUR_CYAN, A_NORMAL


def format_mac(col_width: int, ip: str, stats: PingStats, ping: int):
    fore_col = COLOUR_MAGENTA
    txt = mac_scan_res[ip].strip() if ip in mac_scan_res else 'scanning'
    if len(txt) > col_width:
        txt = txt[:col_width]
    else:
        txt = txt.ljust(col_width)

    return txt, fore_col, COLOUR_BLACK, A_NORMAL


def format_manufacturer(col_width: int, ip: str, stats: PingStats, ping: int):
    fore_col = COLOUR_WHITE
    if ip in mac_scan_res:
        mac = mac_scan_res[ip].strip()
        if ':' in mac:
            oui = mac[0:8].replace(':', '')
            if oui in mac_info_lut:
                m: MACInfo = mac_info_lut[oui]
                txt = f"({m.country.upper()}) {m.company}" if len(m.country) > 0 else f"{m.company}"
            else:
                fore_col = COLOUR_YELLOW
                txt = "?"
        else:
            fore_col = COLOUR_YELLOW
            txt = "n/a"
    else:
        txt = ''  # no mac yet

    if txt == 'Private':
        fore_col = COLOUR_RED

    txt = ' ' + txt
    if len(txt) > col_width:
        txt = txt[:col_width]
    else:
        txt = txt.ljust(col_width)

    return txt, fore_col, COLOUR_BLACK, A_NORMAL


PING_COL_SIZE = 6

col_config = {
    'flag': ColConfig(0, '', 1, format_flag),
    'ip': ColConfig(1, '|ip', 15, format_ip),
    'ping': ColConfig(2, '|ping', PING_COL_SIZE, format_ping),
    'mean': ColConfig(3, '|ave', PING_COL_SIZE, format_mean),
    'best': ColConfig(4, '|min', PING_COL_SIZE, format_best),
    'worst': ColConfig(5, '|max', PING_COL_SIZE, format_worst),
    'sd': ColConfig(6, '|sd', 5, format_sd),
    'up-time': ColConfig(7, '|up', 7, format_up_time),
    'last-outage': ColConfig(8, '|since', 6, format_last_outage),
    'name': ColConfig(9, '|name', 15, format_name),
    'services': ColConfig(10, '|services', 12, format_services),
    'mac': ColConfig(11, '|mac', 14, format_mac),
    'manufacturer': ColConfig(12, '|manufacturer', 20, format_manufacturer),
}


def print_row(row, ping_stats, current_view, screen):
    xpos, ypos = 0, row + 2
    ip = [x for x in ping_stats.keys()][row]
    stats: PingStats = ping_stats[ip]
    ping = stats.last_ping

    for name in current_view:
        config = col_config[name]
        config: ColConfig = config
        txt, fore, back, attr = config.print_func(config.width, ip, stats, ping)
        screen.print_at(txt, xpos, ypos, colour=fore, bg=back, attr=attr)
        xpos += config.width


# ----------------------------------------------------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------------------------------------------------
def main():
    # parse args
    parser = argparse.ArgumentParser(description='Ping things')
    parser.add_argument('--range', type=str, help='network range, eg: 192.168.0.0/24',
                        required=False, default='192.168.0.0/24')
    parser.add_argument('--time_out', type=int, help='time out for ping, in whole seconds', required=False, default=1)
    parser.add_argument('--view', type=str, help='Columns to show', required=False,
                        default="flag,ip,ping,mean,best,worst,sd,up-time,last-outage,name,services,mac,manufacturer")
    parser.add_argument('--bw', help='Black/white mode (colour blind safe).', required=False,
                        action='store_true', default=False)
    args = parser.parse_args()

    # configure app according to args
    ip_range = ipaddress.IPv4Network(args.range)
    time_out = args.time_out
    current_view = [c.strip() for c in args.view.split(",")]

    ping_stats = {}
    # PING_COL_SIZE = int(math.log10(int(time_out * 1000000))) + 1

    def ping_thing(screen):
        unexplored_addresses = [str(ip) for ip in ipaddress.IPv4Network(ip_range)]
        range_len = len(unexplored_addresses)
        re_ping_freq = 2
        last_refresh: int = 0
        num_scans = 1
        last_refresh_time = time.time()
        rescan_chunk_size = int(2 * (math.log2(len(unexplored_addresses) + 1) + 1))
        refresh = True

        # grow the services col to fit
        col_sum = sum([c.width for c in col_config.values()])
        if col_sum < screen.width and 'services' in col_config:
            col_config['services'].width += (screen.width - col_sum)

        while True:
            turbo_scan = num_scans < (range_len / rescan_chunk_size)

            # handle rescan
            if (time.time() - last_refresh_time) >= re_ping_freq:
                # explore known addresses and a few others (but not the whole network).
                effective_chunk_size = rescan_chunk_size * 2 if turbo_scan else rescan_chunk_size
                recheck_pos = (num_scans * effective_chunk_size) % len(unexplored_addresses)
                to_check = [k for k in ping_stats.keys()] + unexplored_addresses[recheck_pos:recheck_pos+effective_chunk_size]
                last_refresh_time = time.time()

                # do scans
                res = scan(to_check, time_out=1)
                new_ips = update_ping_stats(ping_stats, res)

                num_scans += 1

                # port scan up to one new address
                # if not new_ips:
                un_scanned_ips = [k for k in ping_stats.keys() if k not in port_scan_res]
                if len(un_scanned_ips) > 0:
                    ip = un_scanned_ips[0]
                    port_scan_res[ip] = quick_port_scan(ip)

                # flag screen refresh
                refresh = True

                # get mac, scanning 2 at at time
                un_scanned_ips = [k for k in ping_stats.keys() if k not in mac_scan_res]
                for q in range(0, min(len(un_scanned_ips), 2)):
                    ip = un_scanned_ips[q]
                    mac_scan_res[ip] = mac_scan(ip)

            # has the effective second changed?
            if int(time.time()) != last_refresh:
                refresh = True
                last_refresh = int(time.time())

            if refresh:
                # heading
                screen.print_at(f'PING THING (press q to exit)'.center(screen.width),
                                0, 0, colour=COLOUR_MAGENTA, bg=COLOUR_YELLOW)

                # col headings
                heading = "".join([f'{col_config[h].heading}'.ljust(col_config[h].width) for h in current_view])
                heading = heading.ljust(screen.width)
                screen.print_at(heading, 0, 1, colour=COLOUR_YELLOW, bg=COLOUR_MAGENTA, attr=A_NORMAL)

                # list scan results
                for i in range(screen.height-2):
                    if i < len(ping_stats):
                        print_row(i, ping_stats, current_view, screen)
                    else:
                        screen.print_at(" ...", 0, i+2)

                # show info bar at bottom
                screen.print_at(f"   ping unit=ms  scans={num_scans},  network={ip_range},"
                                f"  explore={rescan_chunk_size},  time_out={time_out}".ljust(screen.width),
                                0, screen.height-1, colour=COLOUR_WHITE, bg=COLOUR_BLUE, attr=A_NORMAL)

                refresh = False

            # handle UI
            ev = screen.get_key()
            if ev in (ord('Q'), ord('q')):
                return
            screen.refresh()

    Screen.wrapper(ping_thing)


if __name__ == '__main__':
    load_manufacturer_info()
    # 255 cause the threads are mostly paused anyway, and this make the scans finish faster
    ray.init(num_cpus=255)
    main()





