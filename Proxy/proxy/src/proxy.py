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
error_800 = 'Socket closed during request (800)\n\n'

host = ''
port = 2112
parser = argparse.ArgumentParser()
parser.add_argument("port")
args = parser.parse_args()
porttsring = args.port
port = int(porttsring)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
globalstring = bytearray()


#try parse method that ensures if the objects isn't there the exception is handled
def try_parse(list, element, conn):
    try:
        return list[element]
    except Exception:
        conn.sendall(error_401.encode())

#this method handles clients request when given conn socket and address.
#it loops until all criteria is satisfied for the telnet / browser request
#this way the user has to use the double return to prompt via telnet..
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
                        print('doing request. passing host ' + host + ' path: ' + path)
                        do_request(host, path)
                        host = ''
                        path = ''
                        message = ''
                elif "User-Agent:" in request_list:
                    #do request for browser
                   o = urlparse(request_list[1])
                   host = o.hostname
                   path = o.path
                   if host and path:
                    do_request(host,path)

                elif try_parse(request_list, 0, conn) == 'GET':
                    itsget = 1
                    # need to check request list size
                    if (try_parse(request_list, 2, conn) != 'HTTP/1.0'):
                        # send error
                        conn.sendall(error_501.encode())
                        itsget = 0
                    else:
                        # get...HTTP...get host and if have path for it.
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
    head, seperator, exe = globalstring.partition(b'\r\n\r\n')
    m = hashlib.md5()
    #hash the exe that was given via the server.
    m.update(exe)
    digests = m.hexdigest()

    host = 'hash.cymru.com'
    port = 43
    
    #try connecting to crymu.
    try:
        sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
    except socket.error:
        sys.stderr.write( "error: couldn't connect to registry" )
        conn.sendall(error_800.encode())
        # sys.exit( 1 )

    try:
        sock.connect( (host, port) )
    except socket.error:
        sys.stderr.write( "error: disconnected" )
        conn.sendall(error_800.encode())
        # sys.exit( 2 )

    begin = "begin\r\n"
    end = "end\\r\n"
    # print(digests)
    final = digests + '\r\n'
    # sock.send( begin.encode() )
    sock.send( final.encode() )
    # sock.send( end.encode() )

    #the registery wont send more than this.
    data = sock.recv(2048)

    print(data)
    if "NO_DATA" not in data.decode():
      print("MALWARE")
      nostring = "Malware has been detected in your request"
      conn.sendall(nostring.encode())
    else:
      conn.sendall(globalstring)
    
    sock.close()


#when given a host and path connect, and send.
def do_request(host, path):
    # print('doing queue on host ' + host + ' path: ' + path)
    req_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = 80
    request = "GET " + path + " HTTP/1.0\nHost: " + host + "\n\nConnection: close\n\n"
    req_sock.connect((host, port))
    req_sock.send(request.encode())

    buffer = req_sock.recv(4096)
    globalstring.extend(buffer)
    #get bytes while you still can.
    while(len(buffer) > 0):
        buffer = req_sock.recv(4096)
        globalstring.extend(buffer)

    req_sock.close()
    # print("calling md5")
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