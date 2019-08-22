#!/usr/bin/env python

import sap
import socket
import time

SDP = """v=0
o=mhandley 2890844526 2890842807 IN IP4 126.16.64.4
s=SDP Seminar
i=A Seminar on the session description protocol
u=http://www.cs.ucl.ac.uk/staff/M.Handley/sdp.03.ps
e=mjh@isi.edu (Mark Handley)
c=IN IP4 224.2.17.12/127

t=2873397496 2873404696
a=recvonly
m=audio 49170 RTP/AVP 0
m=video 51372 RTP/AVP 31
m=application 32416 udp wb
a=orient:portrait"""

if __name__ == "__main__":
    # Prepare the socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, sap.DEF_TTL)
    # Grab some info
    myaddr = socket.gethostbyname(socket.gethostname())
    while True:
        # Generate and send a message
        msg = sap.Message()
        msg.setSource(myaddr)
        msg.setPayload(SDP)
        msg.setMsgHash(1)
        print("Sending SAP packet")
        data = msg.pack()
        sock.sendto(data, (sap.DEF_ADDR, sap.DEF_PORT))
        delay = sap.tx_delay(len(data))
        print("Sleeping for {} seconds".format(delay))
        time.sleep(delay)
