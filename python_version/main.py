import threading
import random
import time
import os
from scapy.all import *

OFFLINE = True
INLINE = False
SHOW_ALL_JUDGE = True
SHOW_DEBUG_INFO = False


def pcap_write(filename, buf):
    if os.path.exists(filename):
        with open(filename, "a") as f:
            fdesc = PcapWriter(f)
            fdesc._write_packet(buf)
    else:
        with open(filename, "a") as f:
            fdesc = PcapWriter(f)
            fdesc._write_header(buf)
            fdesc._write_packet(buf)


def icmp_dectection(pkts):
    for buf in pkts:
        try:
            sip = buf[IP].src
            dip = buf[IP].dst
        except Exception, e:
            if SHOW_DEBUG_INFO:
                print e.message
            return
        name = min(sip, dip) + "-" + max(sip, dip)
        try:
            proto = buf[IP].proto
            ihl = buf[IP].ihl
            len = buf[IP].len
            options = buf[IP].options
        except Exception, e:
            if SHOW_DEBUG_INFO:
                print e.message
            return False
        if proto != 1:
            thread.exit()
            return False
        options_len = ihl*4 - 20
        if options_len != 0:
            options_buf = str(buf)[20:ihl*4-1]
            for i in range(0, len-1):
                if options_buf[i] == '\x00':
                    print "ICMP Warning!", name
                    pcap_write("icmp_warning.pcap", buf)
                    return True
            if SHOW_ALL_JUDGE:
                print "safe"
            return False
        else:
            if SHOW_ALL_JUDGE:
                print "safe"
                return False


def ftp_dectection(pkts):
    for buf in pkts:
        try:
            sip = buf[IP].src
            dip = buf[IP].dst
        except Exception, e:
            if SHOW_DEBUG_INFO:
                print e.message
            return
        name = min(sip, dip) + "-" + max(sip, dip)
        try:
            dport = buf[TCP].dport
            sport = buf[TCP].sport
        except Exception, e:
            if SHOW_DEBUG_INFO:
                print e.message
            return
        #print "dport sport", dport, sport
        if dport != 21 and sport != 21:
            return
        ftp_data = str(buf[TCP])[buf[TCP].dataofs*4:-1]
        len = buf[IP].len - buf[IP].ihl*4 - buf[TCP].dataofs*4
        # print "ftp len is ", len
        if dport == 21:
            if str(buf[TCP])[buf[TCP].dataofs*4:buf[TCP].dataofs*4+3] == "MKD" and len >160:
                print "FTP Warning! ", name
                pcap_write("ftp_warning.pcap", buf)
                return True


def check_the_packet(pkts):
    cnt = 4
    while cnt > 0 and threading.active_count() > 400:
        time.sleep(random.random())
        cnt -= 1
    if cnt > 0:
        # why can not i change the order of the two functions?
        ftp_dectection(pkts)
        icmp_dectection(pkts)
    else:
        pcap_write("unchecked.pcap", pkts)
    return False


def sniff_packet():
    threads = []
    if INLINE:
        while True:
            pkts = sniff(iface=None, count=1)
            t = threading.Thread(target=check_the_packet, args=(pkts))
            threads.append(t)
            t.start()
            t.join()
    elif OFFLINE:
        dir = "/mnt/myusbmount/Trojan_Monitor/IP_FLOW2/cisco/warning_ftp.pcap"
        try:
            s1 = PcapReader(dir)
            count = -1
            while count != 0:
                data = s1.read_packet()
                if data is None:
                    break
                else:
                    t = threading.Thread(target=check_the_packet, args=(data))
                    threads.append(t)
                    t.start()
                    t.join()
            s1.close()
        except Scapy_Exception as e:
            print(e)
            return


if __name__ == "__main__":
    pkts = sniff_packet()