"""SocksiPy - Python SOCKS module.
Version 1.00

Copyright 2006 Dan-Haim. All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of Dan Haim nor the names of his contributors may be used
   to endorse or promote products derived from this software without specific
   prior written permission.

THIS SOFTWARE IS PROVIDED BY DAN HAIM "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
EVENT SHALL DAN HAIM OR HIS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMANGE.


This module provides a standard socket-like interface for Python
for tunneling connections through SOCKS proxies.

"""

import socket
import struct
import collections


class Proxy(object):
    """docstring for Proxy"""
    def __init__(self, addr=None, port=None, rdns=True, username=None, password=None):
        super(Proxy, self).__init__()
        self.addr = addr
        self.port = port
        self.rdns = rdns
        self.username = username
        self.password = password
        self.next = None

    def chain(self, proxy):
        self.next = proxy

    def getproxysockname(self):
        """getsockname() -> address info
        Returns the bound IP address and port number at the proxy.
        """
        return self.__proxysockname

    def getproxypeername(self):
        """getproxypeername() -> address info
        Returns the IP and port number of the proxy.
        """
        return self.getpeername()

    def getpeername(self):
        """getpeername() -> address info
        Returns the IP address and port number of the destination
        machine (note: getproxypeername returns the proxy)
        """
        return self.__proxypeername


class Socks5Proxy(Proxy):
    DEFAULT_PORT = 1080

    def __init__(self, *args, **kwargs):
        super(Socks5Proxy, self).__init__(*args, **kwargs)

    def negotiate(self, sock, destaddr, destport):
        """negotiatesocks5(self,destaddr,destport)
        Negotiates a connection through a SOCKS5 server.
        """
        # First we'll send the authentication packages we support.
        if any((self.username, self.password)):
            # The username/password details were supplied to the
            # setproxy method so we support the USERNAME/PASSWORD
            # authentication (in addition to the standard none).
            sock.sendall("\x05\x02\x00\x02")
        else:
            # No username/password were entered, therefore we
            # only support connections with no authentication.
            sock.sendall("\x05\x01\x00")
        # We'll receive the server's response to determine which
        # method was selected
        chosen_auth = sock.recvall(2)
        if chosen_auth[0] != "\x05":
            sock.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        # Check the chosen authentication method
        elif chosen_auth[1] == "\x00":
            # No authentication is required
            pass
        elif chosen_auth[1] == "\x02":
            # Okay, we need to perform a basic username/password
            # authentication.
            sock.sendall(
                "\x01%c%s%c%s" % (
                    chr(len(self.username)),
                    self.username,
                    chr(len(self.password)),
                    self.password
                )
            )
            authstat = sock.recvall(2)
            if authstat[0] != "\x01":
                # Bad response
                sock.close()
                raise GeneralProxyError((1, _generalerrors[1]))
            if authstat[1] != "\x00":
                # Authentication failed
                sock.close()
                raise Socks5AuthError((3, _socks5autherrors[3]))
                # Authentication succeeded
        else:
            # Reaching here is always bad
            sock.close()
            if chosenauth[1] == "\xFF":
                raise Socks5AuthError((2, _socks5autherrors[2]))
            else:
                raise GeneralProxyError((1, _generalerrors[1]))
        # Now we can request the actual connection
        req = "\x05\x01\x00"
        # If the given destination address is an IP address, we'll
        # use the IPv4 address request even if remote resolving was specified.
        try:
            ipaddr = socket.inet_aton(destaddr)
            req = req + "\x01" + ipaddr
        except socket.error:
            # Well it's not an IP number,  so it's probably a DNS name.
            if self.rdns is True:
                # Resolve remotely
                ipaddr = None
                req = req + "\x03" + chr(len(destaddr)) + destaddr
            else:
                # Resolve locally
                ipaddr = socket.inet_aton(socket.gethostbyname(destaddr))
                req = req + "\x01" + ipaddr
        req = req + struct.pack(">H", destport)
        sock.sendall(req)
        # Get the response
        resp = sock.recvall(4)
        if resp[0] != "\x05":
            sock.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        elif resp[1] != "\x00":
            # Connection failed
            sock.close()
            if ord(resp[1]) <= 8:
                raise Socks5Error(ord(resp[1]), _generalerrors[ord(resp[1])])
            else:
                raise Socks5Error(9, _generalerrors[9])
        # Get the bound address/port
        elif resp[3] == "\x01":
            boundaddr = sock.recvall(4)
        elif resp[3] == "\x03":
            resp = resp + sock.recv(1)
            boundaddr = sock.recvall(resp[4])
        else:
            sock.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        boundport = struct.unpack(">H", sock.recvall(2))[0]
        self.__proxysockname = (boundaddr, boundport)
        if ipaddr is not None:
            self.__proxypeername = (socket.inet_ntoa(ipaddr), destport)
        else:
            self.__proxypeername = (destaddr, destport)


class Socks4Proxy(Proxy):
    DEFAULT_PORT = 1080

    def __init__(self, *args, **kwargs):
        super(Socks5Proxy, self).__init__(*args, **kwargs)

    def negotiate(self, sock, destaddr, destport):
        """negotiatesocks4(self,destaddr,destport)
        Negotiates a connection through a SOCKS4 server.
        """
        # Check if the destination address provided is an IP address
        rmtrslv = False
        try:
            ipaddr = socket.inet_aton(destaddr)
        except socket.error:
            # It's a DNS name. Check where it should be resolved.
            if self.rdns is True:
                ipaddr = "\x00\x00\x00\x01"
                rmtrslv = True
            else:
                ipaddr = socket.inet_aton(socket.gethostbyname(destaddr))
        # Construct the request packet
        req = "\x04\x01" + struct.pack(">H", destport) + ipaddr
        # The username parameter is considered userid for SOCKS4
        if self.username is not None:
            req = req + self.username
            req = req + "\x00"
        # DNS name if remote resolving is required
        # NOTE: This is actually an extension to the SOCKS4 protocol
        # called SOCKS4A and may not be supported in all cases.
        if rmtrslv is True:
            req = req + destaddr + "\x00"
        sock.sendall(req)
        # Get the response from the server
        resp = sock.recvall(8)
        if resp[0] != "\x00":
            # Bad data
            sock.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        if resp[1] != "\x5A":
            # Server returned an error
            sock.close()
            if ord(resp[1]) in (91, 92, 93):
                sock.close()
                raise Socks4Error(
                    (ord(resp[1]), _socks4errors[ord(resp[1]) - 90])
                )
            else:
                raise Socks4Error((94, _socks4errors[4]))
        # Get the bound address/port
        self.__proxysockname = (
            socket.inet_ntoa(resp[4:]),
            struct.unpack(">H", resp[2:4])[0]
        )
        if rmtrslv is not None:
            self.__proxypeername = (socket.inet_ntoa(ipaddr), destport)
        else:
            self.__proxypeername = (destaddr, destport)


class HTTPProxy(Proxy):
    DEFAULT_PORT = 8080

    def __init__(self, *args, **kwargs):
        super(Socks5Proxy, self).__init__(*args, **kwargs)

    def negotiate(self, sock, destaddr, destport):
        """negotiatehttp(self,destaddr,destport)
        Negotiates a connection through an HTTP server.
        """
        # If we need to resolve locally, we do this now
        if self.rdns is False:
            addr = socket.gethostbyname(destaddr)
        else:
            addr = destaddr
        sock.sendall(
            "CONNECT %s:%s HTTP/1.1\r\nHost: %s\r\n\r\n" % (
                addr, str(destport), destaddr
            )
        )
        # We read the response until we get the string "\r\n\r\n"
        resp = sock.recv(1)
        while resp.find("\r\n\r\n") == -1:
            resp = resp + sock.recv(1)
        # We just need the first line to check if the connection
        # was successful
        statusline = resp.splitlines()[0].split(" ", 2)
        if statusline[0] not in ("HTTP/1.0", "HTTP/1.1"):
            sock.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        try:
            statuscode = int(statusline[1])
        except ValueError:
            sock.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        if statuscode != 200:
            sock.close()
            raise HTTPError((statuscode, statusline[2]))
        self.__proxysockname = ("0.0.0.0", 0)
        self.__proxypeername = (addr, destport)

defaultproxy = None


class ProxyError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class GeneralProxyError(ProxyError):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class Socks5AuthError(ProxyError):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class Socks5Error(ProxyError):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class Socks4Error(ProxyError):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class HTTPError(ProxyError):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

_generalerrors = (
    "success",
    "invalid data",
    "not connected",
    "not available",
    "bad proxy type",
    "bad input"
)

_socks5errors = (
    "succeeded",
    "general SOCKS server failure",
    "connection not allowed by ruleset",
    "Network unreachable",
    "Host unreachable",
    "Connection refused",
    "TTL expired",
    "Command not supported",
    "Address type not supported",
    "Unknown error"
)

_socks5autherrors = (
    "succeeded",
    "authentication is required",
    "all offered authentication methods were rejected",
    "unknown username or invalid password",
    "unknown error"
)

_socks4errors = (
    "request granted",
    "request rejected or failed",
    "request rejected because SOCKS server cannot connect to identd\
 on the client",
    "request rejected because the client program and identd report\
 different user-ids",
    "unknown error"
)


def setdefaultproxy(proxy):
    """setdefaultproxy(proxytype, addr[, port[, rdns[, username[, password]]]])
    Sets a default proxy which all further proxysocket objects will use,
    unless explicitly changed.
    """
    global defaultproxy
    defaultproxy = proxy


class ProxySocket(socket.socket):
    """proxysocket([family[, type[, proto]]]) -> socket object

    Open a SOCKS enabled socket. The parameters are the same as
    those of the standard socket init. In order for SOCKS to work,
    you must specify family=AF_INET, type=SOCK_STREAM and proto=0.
    """

    def __init__(self, *args, **kwargs):
        super(ProxySocket, self).__init__(*args, **kwargs)
        self.proxy = defaultproxy
        self.__proxysockname = None
        self.__proxypeername = None

    def recvall(self, bytes):
        """recvall(bytes) -> data
        Receive EXACTLY the number of bytes requested from the socket.
        Blocks until the required number of bytes have been received.
        """
        data = ""
        while len(data) < bytes:
            data = data + self.recv(bytes-len(data))
        return data

    def setproxy(self, proxy):
        """setproxy(proxytype, addr[, port[, rdns[, username[, password]]]])
        Sets the proxy to be used.
        proxytype -The type of the proxy to be used. Three types
                are supported: PROXY_TYPE_SOCKS4 (including socks4a),
                PROXY_TYPE_SOCKS5 and PROXY_TYPE_HTTP
        addr -		The address of the server (IP or DNS).
        port -		The port of the server. Defaults to 1080 for SOCKS
                servers and 8080 for HTTP proxy servers.
        rdns -		Should DNS queries be preformed on the remote side
                    (rather than the local side). The default is True.
                Note: This has no effect with SOCKS4 servers.
        username -	Username to authenticate with to the server.
                The default is no authentication.
        password -	Password to authenticate with to the server.
                Only relevant when username is also provided.
        """
        self.proxy = proxy

    def connect(self, destpair):
        """connect(self,despair)
        Connects to the specified destination through a proxy.
        destpar - A tuple of the IP/DNS address and the port number.
        (identical to socket's connect).
        To select the proxy server use setproxy().
        """

        if self.proxy is not None:
            portnum = self.proxy.port if self.proxy is not None else getattr(
                self.proxy.__class__, "DEFAULT_PORT"
            )
            dest = destpair
            destpair = (self.proxy.addr, portnum)

        super(ProxySocket, self).connect((destpair[0], destpair[1]))

        if self.proxy is not None:
            self.proxy.negotiate(self, dest[0], dest[1])

for subclass in Proxy.__subclasses__():
    setattr(socket, subclass.__name__, subclass)

socket.socket = ProxySocket
socket.Proxy = Proxy
socket.setdefaultproxy = setdefaultproxy
