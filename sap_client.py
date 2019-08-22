#!/usr/bin/env python
# 
import sap
import socket
import struct

if __name__ == "__main__":
    # Perpare the socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", sap.DEF_PORT))
    mreq = struct.pack("4sl", socket.inet_aton(sap.DEF_ADDR), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    while True:
        data = sock.recv(4096)
	msg = sap.Message()
	msg.unpack(data)
	print "Received SAP:\n", msg
