#!/usr/bin/env python3


from scapy.all import sniff
from scapy.all import Raw

from binrw import Buffer
from message import Msg


def raw(pa):
    return bytes(pa.getlayer(Raw))


def msgHandler(pa, buf, action):
    buf += raw(pa)
    msg = Msg(buf)
    while msg:
        action(msg)
        msg = Msg(buf)


def launch(action):
    print('DofLog is on!\nctrl+c to stop')
    buf = Buffer()
    sniff(filter='tcp port 5555', lfilter=lambda p: p.haslayer(
        Raw), prn=lambda p: msgHandler(p, buf, action))
    print('\nDofLog has been stopped!')


def action(msg):
    """
    action to execute on the message
    """
    print(msg.id)
