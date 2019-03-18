#!/usr/bin/env python

import rospy
import time
import logging
import can
import re
import dpkt
import datetime
import socket


from dpkt.compat import compat_ord
from std_msgs.msg import String
from std_msgs.msg import Float32
from can.message import Message
from string import *




def mac_addr(address):

    return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):

    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def print_packets(pcap):
    framecount = 0
    for timestamp, buf in pcap:

        #print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        #print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)

        # Make sure the Ethernet data contains an IP packet
        #if not isinstance(eth.data, dpkt.ip.IP):
        #    print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
        #    continue

        ip = eth.data
        UDP = ip.data

        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        framecount += 1

        if framecount > 0 and ip.len > 100:
            print "FrameCount: %d Timestamp %f" % (framecount, timestamp)#-last_time) 
        last_time = timestamp


        # Print out the info , timestamp - last_time
        #print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
              #(inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))
        #print('data: %s\n' % (repr(UDP.data)))
        print('SPort: %d, Dport: %d' % (UDP.sport, UDP.dport))


def readCap():
    with open('/home/dvt/Desktop/march11/2019_Mar_11_091103_eth1_part001.cap', 'rb') as f:

        pcap = dpkt.pcap.Reader(f)
        print_packets(pcap)
        
        


if __name__ == '__main__':
    readCap() 