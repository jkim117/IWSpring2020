from sys import argv
import dpkt
import csv
import socket
import ipaddress
import pickle
import crc16
import numpy as np

# Data structure and global variables
allowed_ips = []
banned_ips = []

knownlistDict = {} # Key is knowlist domain, values are number of dns, number of packets, number of bytes, number missed dns, estimated packets, estimated bytes
known_domains = []

netassayTable = {} # Key is concatentation of serever IP/client IP. Value is a knownlist domain name

def is_subnet_of(a, b):
    return (b.network_address <= a.network_address and b.broadcast_address >= a.broadcast_address)

def parse_dns_response(ip_packet, ts):
    # Check if it is in the allowed or banned IP lists
    clientIP = socket.inet_ntoa(ip_packet.dst)
    cip_object = ipaddress.ip_network(clientIP)
    allowed = False
    for ip in allowed_ips:
        if is_subnet_of(cip_object, ip):
            allowed = True
            break

    if (not allowed):
        return

    for ip in banned_ips:
        if is_subnet_of(cip_object, ip):
            return


    dns = dpkt.dns.DNS(ip_packet.data.data)
    answers = dns.an

    domain = answers[0].name
    domain_name = domain.split('.')

    parseable = True

    # Parser limitations
    if (len(domain_name) > 4):
        parseable = False
    for part in domain_name:
        if (len(part) > 15):
            parseable = False

    if (parseable):
        for rr in answers:
            if (rr.type != 1):
                continue
            if (rr.type == 1): #DNS.A
                entry = knownlistDict['*']
                knownlistDict['*'][0] = knownlistDict['*'][0] + 1
                
                serverIP = socket.inet_ntoa(rr.rdata)

                key = clientIP + serverIP

                netassayTable[key] = '*'
                break
    else:
        for rr in answers:
            if (rr.type != 1):
                continue
            if (rr.type == 1): #DNS.A
                if domain_name not in knownlistDict:
                    knownlistDict[domain_name] = [0, 0, 0, 0, 0, 0]
                
                knownlistDict[domain_name][0] = knownlistDict[domain_name][0] + 1
                
                serverIP = socket.inet_ntoa(rr.rdata)

                key = clientIP + serverIP

                netassayTable[key] = domain_name
                break

def parse_tcp(packet_len, ip_packet, ts):
    source = socket.inet_ntoa(ip_packet['src']) #server
    dest = socket.inet_ntoa(ip_packet['dst']) #client
    
    key = dest + source
    if key in netassayTable:
        d = netassayTable[key]
        knownlistDict[d][1] = knownlistDict[d][1] + 1
        knownlistDict[d][2] = knownlistDict[d][2] + packet_len
        


def matchDomain(known, domain):
    knownparts = known.split('.')
    domainparts = domain.split('.')
    if len(knownparts) != len(domainparts):
        return False
    
    for i in range(0, len(knownparts)):
        if (knownparts[i] == '*'):
            continue
        if (knownparts[i] != domainparts[i]):
            return False
    return True


# parse the command line argument and open the file specified
if __name__ == '__main__':
    if len(argv) != 6:
        print('usage: python netassay_python3_p4sim.py pickleFile allowed_dns_dst.txt banned_dns_dst.txt outfilename')
        exit(-1)
    
    # Parse allowed IP and banned IP files
    allowed_ip_file = open(argv[2], 'r')
    allowed_ip_list = allowed_ip_file.read().split()
    allowed_ip_file.close()
    for ip in allowed_ip_list:
        allowed_ips.append(ipaddress.ip_network(ip))

    banned_ip_file = open(argv[3], 'r')
    banned_ip_list = banned_ip_file.read().split()
    banned_ip_file.close()
    for ip in banned_ip_list:
        banned_ips.append(ipaddress.ip_network(ip))

    knownlistDict['*'] = [0, 0, 0, 0, 0, 0]

    f = open(argv[1], 'rb')
    pcap_obj = pickle.load(f)
    f.close()

    for p in pcap_obj:
        ts = p[0]
        dns_code = p[1]
        ip = p[2]

        # For each packet parse the dns responses
        if (dns_code == -1):
            try:
                parse_dns_response(ip, ts)
            except Exception as e:
                
                continue
        else:
            parse_tcp(dns_code, ip, ts)

    for i in knownlistDict.keys():
        num_packets = knownlistDict[i][1]
        num_bytes = knownlistDict[i][2]
        num_missed = knownlistDict[i][3]
        num_dns = knownlistDict[i][0]
        if (num_dns > 0 and num_missed < num_dns):
            knownlistDict[i][4] = num_packets / (1 - (num_missed / num_dns))
            knownlistDict[i][5] = num_bytes / (1 - (num_missed / num_dns))


    with open(argv[5], 'w') as csvfile:
        w = csv.writer(csvfile)
        w.writerow(["Domain", "Number of DNS requests", "Missed DNS requests missed", "Number of Packets", "Number of Bytes", "Estimated Packets", "Estimated Bytes"])

        for i in knownlistDict.items():
            w.writerow([i[0], i[1][0], i[1][3], i[1][1], i[1][2], i[1][4], i[1][5]])

            


