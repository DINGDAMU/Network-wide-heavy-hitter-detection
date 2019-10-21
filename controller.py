# !/usr/bin/python
# -*- coding:utf-8 -*-
# ###########################
# File Name: controller.py
# Author: dingdamu
# Mail: dingdamu@gmail.com
# Created Time: 2019-02-07 16:43:08
# ###########################

import socket
import struct
import subprocess
from scapy.all import *

num_switch = 3
sampleList_size = 10
port = 22222
fraction = 0.0005
sniff_port = "veth0"
interval = 5


def readRegister(register, thrift_port):
        p = subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(thrift_port)],
                                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                                      stderr=subprocess.PIPE)
        stdout, stderr = p.communicate(input=("register_read %s" % (register)).encode())
        reg = list(stdout.decode().strip().split("= ")[1].split("\n")[0].split(", "))
        reg = list(map(int, reg))
        return reg

def resetState(thrift_port):
        p = subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(thrift_port)],
                                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                                      stderr=subprocess.PIPE)
        commands = 'register_reset hh_r\n'+'register_reset packet_tot\n'+\
            'register_reset sampleList_src\n'+'register_reset sampleList_dst\n'\
            + 'register_reset sampleList_count\n'
        for i in range(1, 11, 1):
            commands += "register_reset heavy_hitter_register%s\n" %str(i)
        p.communicate(input=commands.encode())




def globalHH():
    whole_network_volume = 0
    for i in (range(num_switch)):
        locals()['src' + str(i+1)] = readRegister('sampleList_src', int(port+i))
        locals()['dst' + str(i+1)] = readRegister('sampleList_dst', int(port+i))
        locals()['count' + str(i+1)] = readRegister('sampleList_count', int(port+i))
    for i in (range(num_switch)):
        for j in (range(sampleList_size)):
            if locals()['src' + str(i+1)][j] != 0 and\
                    locals()['dst' + str(i+1)][j] != 0:
                flow_key = str(locals()['src' + str(i+1)][j] )+" "+str(locals()['dst' + str(i+1)][j] );
                if flow_key not in global_sampleList:
                    global_sampleList[flow_key] = int(locals()['count' + str(i+1)][j])
                elif global_sampleList[flow_key] > int(locals()['count' + str(i+1)][j]):
                     global_sampleList[flow_key] = int(locals()['count' + str(i+1)][j])
    print ('Global sample list:')
    print (global_sampleList)
    for value in global_sampleList.values():
        whole_network_volume += value
    global_threshold = whole_network_volume * fraction
    print ('Global threshold:')
    print (global_threshold)
    for key in global_sampleList.keys():
        if global_sampleList[key] > global_threshold:
            hh_keys.append(key)
    print ('Global heavy hitter keys:')
    for key in hh_keys:
        keylist = key.split()
        src = int(keylist[0])
        dst = int(keylist[1])
        print (str(int2ip(src)) + " " + str(int2ip(dst)))

def int2ip(num):
    return socket.inet_ntoa(struct.pack("!I", num))

def inttoip(num):
            s = bin(num)[2:]
            s = s.zfill(32)
            g = []
            h = []
            for i in xrange(0,32,8):
                g.append(s[i:i+8])
            for temp in g:
                    h.append(str(int(temp,2)))
                    e = ".".join(h)
            return e


def getFlag(packet):
    rep = raw(packet)[0:1]
    return rep


def stopfilter(packet):
    if raw(packet)[0:1] == b'\x80':
        globalHH()
        return True
    else:
        return False


def resetAll():
    resetState(22222)
    resetState(22223)
    resetState(22224)


i = 0
# 10 time intervals
while i < 10:
    global_sampleList = {}
    hh_keys = []
    print("The sniffing port is set to: [{}]".format(sniff_port))
    sniff(iface=sniff_port, prn=getFlag, stop_filter=stopfilter, timeout=interval)
    resetAll()
    i += 1

