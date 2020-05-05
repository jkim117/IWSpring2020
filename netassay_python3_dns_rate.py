from sys import argv
import dpkt
import csv
import socket
import ipaddress
import datetime

TOTAL_DNS_RESPONSE_COUNT = 0
dns_timestamps = []
dns_counts = []

allowed_ips = []
banned_ips = []

netassayTable = {} # Key is concatentation of serever IP/client IP. Values is a tuple of domain name, num packets, num of bytes
netassayTableByDomain = {} # Key is domain name

def is_subnet_of(a, b):
    return (b.network_address <= a.network_address and
                    b.broadcast_address >= a.broadcast_address)

def parse_dns_response(ip_packet, ts):
    global TOTAL_DNS_RESPONSE_COUNT

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

    TOTAL_DNS_RESPONSE_COUNT = TOTAL_DNS_RESPONSE_COUNT + 1
    dns_counts.append(TOTAL_DNS_RESPONSE_COUNT)
    dns_timestamps.append(ts)

    dns = dpkt.dns.DNS(ip_packet.data.data)
    answers = dns.an

    domain = answers[0].name

    # Counter number of DNS responses by domain name
    if domain in netassayTableByDomain:
        netassayTableByDomain[domain][0] = netassayTableByDomain[domain][0] + 1
    else:
        netassayTableByDomain[domain] = [1, 0, 0]


    for rr in answers:
        if (rr.type == 1): #DNS.A
            serverIP = socket.inet_ntoa(rr.rdata)

            key = clientIP + serverIP

            # Entry already exists. Hopefully doesn't occur
            if key in netassayTable:
                entry = netassayTable[key]
                if (entry[0] != domain):
                    netassayTable[key][0] = domain
            else:
                # Create new entry
                netassayTable[key] = [domain, 0, 0]

            break
        

def parse_tcp(ip_packet):
    source = socket.inet_ntoa(ip_packet.src) #client
    dest = socket.inet_ntoa(ip_packet.dst) #server

    key = source + dest
    if key in netassayTable:
        entry = netassayTable[key]
        netassayTable[key] = [entry[0], entry[1] + 1, entry[2] + ip_packet.len]
    else:
        key = dest + source
        if key in netassayTable:
            entry = netassayTable[key]
            netassayTable[key] = [entry[0], entry[1] + 1, entry[2] + ip_packet.len]

def matchDomain(known, domain, n):
    knownparts = known.split('.')
    domainparts = domain.split('.')
    if len(knownparts) != len(domainparts):
        return False
    
    for i in range(0, len(knownparts)):
        if (n!=-1):
            if (len(domainparts[i]) > n):
                return False

        if (knownparts[i] == '*'):
            continue
        if (knownparts[i] != domainparts[i]):
            return False
    return True


# parse the command line argument and open the file specified
if __name__ == '__main__':
    if len(argv) != 5:
        print('usage: python pcapanalysis.py capture.pcap knownlist.txt allowed_dns_dst.txt banned_dns_dst.txt')
        exit(-1)
    
    allowed_ip_file = open(argv[3], 'r')
    allowed_ip_list = allowed_ip_file.read().split()
    allowed_ip_file.close()
    for ip in allowed_ip_list:
        allowed_ips.append(ipaddress.ip_network(ip))

    banned_ip_file = open(argv[4], 'r')
    banned_ip_list = banned_ip_file.read().split()
    banned_ip_file.close()
    for ip in banned_ip_list:
        banned_ips.append(ipaddress.ip_network(ip))

    with open(argv[1], 'rb') as f:
        #try:
        #    pcap_obj = dpkt.pcap.Reader(f)
        #except:
        pcap_obj = dpkt.pcapng.Reader(f)

        i = 0
        initialTime = 0

        for ts, buf in pcap_obj:
            eth = dpkt.ethernet.Ethernet(buf)

            if (i == 0):
                initialTime = ts
            

            print(datetime.datetime.utcfromtimestamp(ts))

            if (eth.type != 2048): # If not IPV4
                continue
            ip = eth.data
            protocol = ip.p

            try:
                if (protocol == 17 and ip.data.sport == 53):
                    timeStamp = ts - initialTime
                    parse_dns_response(ip, timeStamp)
                else:
                    parse_tcp(ip)
            except:
                continue


    for i in netassayTable.values():
        netassayTableByDomain[i[0]][1] = netassayTableByDomain[i[0]][1] + i[1]
        netassayTableByDomain[i[0]][2] = netassayTableByDomain[i[0]][2] + i[2]

    f = open('DNS-RATE_COUNT.txt', 'w')
    for n in dns_counts:
        f.write(str(n)+'\n')

    f.close()

    f = open('DNS-RATE_TIME.txt', 'w')
    for n in dns_timestamps:
        f.write(str(n) + '\n')

    f.close()




            


