# Session Annoucements according to RFC2974 in Python

### Original code by Michael Ihde, adapted to Python 3 by Thomas Schlien

1. Introduction

This python module provides support for building Session Annoucements according
to RFC2974.  For it to be useful, you will also need a way to generate/parse
Session Descriptions (RFC2327), which is not part of this module (I'm working
on building the SDP module).

2. License

The SAP module is released under the LGPL, Copyright (C) 2007 Michael Ihde

The examples (sap_client.py and sap_server.py) are released in the public domain.

3. Installation

The package installation follows the python distutils standard.  A typical
installation can be performed with this command:

    `sudo python setup.py install`

I've provided two very basic examples of using the sap module (a client and a
server).  Both run with no arguments.  Use CTRL-C to exit.

IV. Known Issues

Currently the code has very little documentation.

I've only tested this on Linux platforms.

I haven't fully tested encrypted or authenticated packets.
