#!/usr/bin/env python
# Copyright (C) 2007 Michael Ihde
# Released under the LGPL version 2.1
"""Provides support for creating messages conforming to the
Session Announcement Protocol.
"""
import struct
import socket
import random
import time
import warnings
import zlib

# Define some contants from the RFC
DEF_ADDR = "224.2.127.254"
DEF_PORT = 9875
DEF_TTL = 225
DEF_BW_LIMIT = 4000 # bits/second
DEF_MIN_DELAY = 300

AUTH_PGP = 0
AUTH_CMS = 1

def tx_delay(msg_size, no_of_msgs=1, bwlimit=DEF_BW_LIMIT):
    """Returns the amount of time before another SAP message can
    be sent, assuming one was just sent.
    """
    interval = max(DEF_MIN_DELAY, (8*no_of_msgs*msg_size)/bwlimit)
    offset = random.uniform(0, float(interval)*2/3) - (float(interval)/3)
    return interval + int(offset)

def next_tx_time(msg_size, last_time=None, no_of_msgs=1, bwlimit=DEF_BW_LIMIT):
    """Return the absolute time for the next SAP tranmission.  The no_of_msgs is
    the number of annoucements being made for one set of multicast sessions.  If
    the last_time is not given, it assumes that an SAP was just sent.
    """
    if last_time:
        tp = last_time
    else:
        tp = time.time()
    return tp + tx_delay(msg_size, no_of_msgs, bwlimit)

class SAPException(Exception):
    pass

class Message:
    """A SAP Message, which follows RFC2947.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | V=1 |A|R|T|E|C|   auth len    |         msg id hash           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    :                originating source (32 or 128 bits)            :
    :                                                               :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    optional authentication data               |
    :                              ....                             :
    *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*
    |                      optional payload type                    |
    +                                         +-+- - - - - - - - - -+
    |                                         |0|                   |
    + - - - - - - - - - - - - - - - - - - - - +-+                   |
    |                                                               |
    :                            payload                            :
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    _SAP_VERSION = 5
    _ADDRESS_TYPE = 4
    _RESERVED = 3
    _MESSAGE_TYPE = 2
    _ENCRYPTION = 1
    _COMPRESSION = 0

    _SAP_VERSION_1 = 0x01 << _SAP_VERSION
    _IPV6_ADDR = 0x01 << _ADDRESS_TYPE
    _ANNOUNCEMENT = 0x00 << _MESSAGE_TYPE
    _DELETION = 0x01 << _MESSAGE_TYPE
    _ENCRYPTED = 0x01 << _ENCRYPTION
    _COMPRESSED = 0x01 << _COMPRESSION

    def __init__(self, msg_hash=0, src_ip=(socket.AF_INET, "0.0.0.0"), deletion=False, compression=False):
        self._payload_type = "application/sdp"
        self._msg_hash = msg_hash
        self._src_ip = src_ip
        self._payload = ""
        self._deletion = deletion
        self._compress = False

    def setSource(self, ip_string, address_family=socket.AF_INET):
        self._src_ip = (address_family, ip_string)

    def setPayload(self, data, type="application/sdp"):
        self._payload = str.encode(data)

    def setCompression(self, compress):
        self._compress = compress

    def setMsgHash(self, msg_hash):
        self._msg_hash = msg_hash

    def setDeletion(self, deletion):
        self._deletion = deletion

    def _pack_auth_data(self, data, type):
        """Pack authentication data following RFC2947.  This class
        is merely a container, it does not provide PGP or CMS authentication
        functionality.  The type should be either AUTH_PGP or AUTH_CMS, but
        can be any number 0-15"""
        _AUTH_VERSION_1 = 0x01 <<  5
        _PADDING = 0x01 << 4

        if type < 0 or type > 15:
            warnings.warn("Invalid authentication type")
        if not type in [AUTH_PGP, AUTH_CMS]:
            warnings.warn("Non standard authentication type.  Only PGP and CMS are supported.")

        if len(data) > 0:
            fbyte = _AUTH_VERSION | int(type)
            padbytes = len(data) % 4
            if padbytes != 0:
                # Padding is necessary
                fbyte = fbyte | _PADDING
                # The RFC only specifies the content of the last padding
                # byte, so let's do the simplest thing and have all padding
                # bytes be the same
                paddata = struct.pack("B", padbytes)
                data.extend([paddata for x in xrange(padbytes)])
            # Double check our algorithm
            assert( len(data)%4 == 0 )
            authheader = []
            authheader.append(struct.pack("B", fbyte))
            authheader.append(self._data)
            return "".join(authheader)
        else:
            return ""

    def unpack(self, data, decryptor=None):
        """Unpacks the data into this class, returns the authentication data
        and authentication type.  If decryption needs to be performed a callable
        method must be passed in.  If the received packet is not encrypted this
        function will be called."""
        fbyte, auth_len, msg_hash  = struct.unpack("BBH", data[0:4])
        self._msg_hash = msg_hash
        sap_version = (fbyte & 0xE0) >> self._SAP_VERSION
        if sap_version != 0x01:
            warnings.warn("Unsupported SAP version received")

        self._compress = (fbyte & self._COMPRESSED) != 0x00
        self._deletion = (fbyte & self._DELETION) != 0x00

        if (fbyte & self._IPV6_ADDR) != 0x00:
            ip_type = socket.AF_INET6
            ip_data = data[4:20]  # TODO: How do we unpack this?
            auth_data = data[20:20+auth_len]
            payload_and_type = data[20+auth_len:]
        else:
            ip_type = socket.AF_INET
            ip_data = data[4:8]
            auth_data = data[8:8+auth_len]
            payload_and_type = data[8+auth_len:]
        string_ip = socket.inet_ntop(ip_type, ip_data)
        self._src_ip = (ip_type, string_ip)

        # For payload type we have to search until finding
        # a null unless the first three bytes equal 'v=0'
        # The standard first line for SDP
        if payload_and_type[0:3] == "v=0":
            self._payload = payload_and_type
        else:
            null_index = payload_and_type.index(b'\0')
            self._payload_type = payload_and_type[0:null_index]
            self._payload = payload_and_type[null_index+1:]

        # Finally allow the payload to be decrypted
        encrypted = (fbyte & self._ENCRYPTED) != 0x00
        if encrypted:
            try:
                self._payload = decryptor(self._payload)
            except TypeError:
                warnings.warn("Received encrypted packet but no decryptor provided")

        compressed = (fbyte & self._COMPRESSED) != 0x00
        if compressed:
            self._compress = True
            self._payload = zlib.decompress(self._payload)

    def pack(self, authenticator=None, auth_type=None, encryptor=None):
        fbyte = self._SAP_VERSION_1
        payload = self._payload

        # Following the RFC, compression must happen first
        if self._compress:
            fbyte = fbyte | self._COMPRESSED
            payload = zlib.compress(self._payload)
        else:
            fbyte = fbyte & ~(self._COMPRESSED)

        # Set other fields in the first bytes, as necessary
        if self._src_ip[0] == socket.AF_INET6:
            fbyte = fbyte | self._IPV6_ADDR
        else:
            fbyte = fbyte & ~(self._IPV6_ADDR)

        if self._deletion:
            fbyte = fbyte | self._DELETION
        else:
            fbyte = fbyte & ~(self._DELETION)

        # If we have an encryptor, use it
        if callable(encryptor):
            payload = encryptor(payload)
            fbyte = fbyte | self._ENCRYPTED
        else:
            fbyte = fbyte & ~(self._ENCRYPTED)

        # Build up the message
        sap = []
        sap.append(struct.pack("BBH", fbyte, 0, self._msg_hash))
        sap.append(socket.inet_pton(*self._src_ip))
        sap.append(str.encode(self._payload_type + '\0'))
        sap.append(payload)
        result = b''.join(sap)

        # See if we want to add authentication
        if callable(authenticator):
            signature = authenticator(result)
            auth_data = pack_auth_data(signature, auth_type)
            # Now patch up the packet with the authenticated data
            sap[0] = struct.pack("BBH", fbyte, len(auth_data), self._msg_hash)
            sap.insert(2, str(auth_data))
            result = "".join(sap)

        if len(result) > 1024:
            warnings.warn("RFC2947 RECOMMENDS that SAP packets be less that 1kByte")
        return result

    def __str__(self):
        lines = []
        lines.append("Source: %s" % self._src_ip[1])
        lines.append("Msg Hash: %s" % self._msg_hash)
        lines.append("Payload Type: %s" % self._payload_type)
        lines.append(repr(self._payload))
        return "\n".join(lines)

    def __eq__(self, other):
        result = (self._payload_type == other._payload_type) & \
                 (self._msg_hash == other._msg_hash) &\
                 (self._src_ip == other._src_ip) & \
                 (self._payload == other._payload) & \
                 (self._deletion == other._deletion) & \
                 (self._compress == other._compress)
        return result

    def __ne__(self, other):
        return not self.__eq__(self, other)

if __name__ == "__main__":
    # TODO: Move this into a unittest
    msg1 = Message()
    msg1.setSource("192.168.1.10", socket.AF_INET)
    msg2 = Message()
    data = msg1.pack()
    msg2.unpack(data)
    print(msg1)
    print(msg2)
