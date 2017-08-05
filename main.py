#!/usr/bin/env python3

# Fix for the issue https://github.com/louisabraham/DofLog/issues/2#issuecomment-320434061
# See https://stackoverflow.com/questions/24812604/hide-scapy-warning-message-ipv6
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

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
    print('DofLog is on!\nPress Ctrl+C to stop')
    buf = Buffer()
    sniff(filter='tcp port 5555', lfilter=lambda p: p.haslayer(
        Raw), prn=lambda p: msgHandler(p, buf, action))
    print('\nDofLog has been stopped!')


def action(msg):
    """
    action to execute on the message
    """
    print(msg.id)

if __name__ == "__main__":
    launch(action)
    
