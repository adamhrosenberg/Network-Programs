#!/usr/bin/env python3

#######
# Adam Rosenberg
# u0751643
# CS 4480
# Proxy. Please run with python3 proxy.py <port>.
# Port can be be between 2112-2120 on CADE.
# i.e. python3 proxy.py 2112

import socket
from urllib.parse import urlparse
import sys
import getopt
import multiprocessing
from _thread import *
import argparse
import hashlib

error_400 = 'Bad Request  (400). Proxy only handles GET request and header declarations.\n\n'
error_501 = 'Not implemented (501). Only supports HTTP/1.0\n\n'
error_300 = 'Could not decode (300)\n\n'
error_200 = 'IO error (200)\n\n'
error_401 = 'Invalid request syntax (401)\n\n'

host = ''
port = 2112
parser = argparse.ArgumentParser()
parser.add_argument("port")
args = parser.parse_args()
porttsring = args.port
port = int(porttsring)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
globalstring = bytearray()
def try_parse(list, element, conn):
    try:
        return list[element]
    except Exception:
        conn.sendall(error_401.encode())

def handle_client(conn, address):
    host = ''
    path = ''
    itsget = 0
    message = ''
    while True:
        try:
            data = conn.recv(4096)
            try:
                message = data.decode('utf-8')
            except Exception:
                conn.sendall(error_300.encode())
            #print('message... ' + message)
            request_list = message.split()  # [0] = get, [1] = total url. [2] = HTTP1
            if(len(request_list) != 0 or message == '\r\n'):
                if (message == '\r\n'):
                    if host and path:
                        # print('doing request. passing host ' + host + ' path: ' + path)
                        do_request(host, path)
                        host = ''
                        path = ''
                        message = ''
                elif "User-Agent:" in request_list:
                   #handle browser.
                   # print('victory..')
                   o = urlparse(request_list[1])
                   host = o.hostname
                   path = o.path
                   do_request(host,path)
                elif try_parse(request_list, 0, conn) == 'GET':
                    itsget = 1
                    # need to check request list size
                    if (try_parse(request_list, 2, conn) != 'HTTP/1.0'):
                        # send error
                        conn.sendall(error_501.encode())
                        itsget = 0
                    else:
                        # get...HTTP...
                        o = urlparse(request_list[1])
                        host = o.hostname
                        if not host:
                            path = request_list[1]
                        else:
                            path = o.path

                elif request_list[0] == 'Host:':
                    host = request_list[1]
                else:
                    if not itsget:
                        conn.sendall(error_400.encode())
                        itsget = 0
                    else:
                        if (len(request_list) == 2):
                            print('Adding header..')
                        else:
                            conn.sendall(error_400.encode())
                            itsget = 0

        except IOError:
            conn.sendall(error_200.encode())


def md5():
    #do md5 on globalstring
    
    m = hashlib.md5(globalstring)
    digests = m.hexdigest()

    host = 'hash.cymru.com'
    port = 43
    # digests = 'f40581e27c69d18f8c12c1297622866e'
    # digests = '2d75cc1bf8e57872781f9cd04a529256'
    
    try:
        sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        # sock.settimeout( 100 )
        # sock.setblocking(0)
    except socket.error:
        sys.stderr.write( "error:%s\n" % msg[1] )
        sys.exit( 1 )

    try:
        
        sock.connect( (host, port) )
    except socket.error:
        sys.stderr.write( "error: " )
        sys.exit( 2 )

    begin = "begin\r\n"
    end = "end\\r\n"
    print(digests)
    sock.send( begin.encode() )
    sock.send( digests.encode() )
    sock.send( end.encode() )

 
    data = sock.recv(2048)

    print(data)
    if "NO_DATA" not in data.decode():
      print("MALWARE")
    else:
      conn.sendall(globalstring)
    
    sock.close()


def do_request(host, path):
    # print('doing queue on host ' + host + ' path: ' + path)
    req_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = 80
    request = "GET " + path + " HTTP/1.0\nHost: " + host + "\n\nConnection: close\n\n"
    req_sock.connect((host, port))
    req_sock.send(request.encode())
    buffer = req_sock.recv(4096)
    globalstring.extend(buffer)
    # conn.sendall(buffer)
    # temp = buffer

    # buffer = ''
    while(len(buffer) > 0):
        buffer = req_sock.recv(4096)
        globalstring.extend(buffer)
        # try:
        #     conn.sendall(buffer)
        # except Exception:
        #     conn.sendall(error_200.encode())
    req_sock.close()
    # conn.sendall(globalstring)

    md5()


if __name__ == "__main__":
    try:
        s.bind((host, port))
        print(port)
    except socket.error as e:
        print(str(e))
    s.listen(1)
    while True:
        conn, addr = s.accept()
        # print('proxy connected to client @: ' + addr[0] + ':' + str(addr[1]))
        process = multiprocessing.Process(target=handle_client, args=(conn, addr))
        process.daemon = True
        process.start()
        print("Started process %r", process)
        # handle_client(conn, addr)