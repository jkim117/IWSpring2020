from sys import argv
import dpkt
import csv
import socket
import ipaddress

allowed_ips = []
banned_ips = []

netassayTable = {} # Key is concatentation of serever IP/client IP. Values is a tuple of domain name, num packets, num of bytes
netassayTableByDomain = {} # Key is domain name

def is_subnet_of(a, b):
    return (b.network_address <= a.network_address and
                    b.broadcast_address >= a.broadcast_address)

def parse_dns_response(ip_packet):
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

        for ts, buf in pcap_obj:
            eth = dpkt.ethernet.Ethernet(buf)

            if (eth.type != 2048): # If not IPV4
                continue
            ip = eth.data
            protocol = ip.p

            try:
                if (protocol == 17 and ip.data.sport == 53):
                    parse_dns_response(ip)
                else:
                    parse_tcp(ip)
            except:
                continue


    for i in netassayTable.values():
        netassayTableByDomain[i[0]][1] = netassayTableByDomain[i[0]][1] + i[1]
        netassayTableByDomain[i[0]][2] = netassayTableByDomain[i[0]][2] + i[2]


    # Create knownlist csv if argument provided
    knownlist = open(argv[2], 'r')
    domains = knownlist.read().split()
    knownlist.close()

    knownlistDict = {} # Key is knowlist domain, values are number of dns, number of packets, number of bytes
    for d in domains:
        knownlistDict[d] = [0, 0, 0]

    stats = [0, 0, 0]

    for i in netassayTableByDomain.items():
        for d in domains:
            if (matchDomain(d, i[0], -1)):
                stats = [stats[0] + i[1][0], stats[1] + i[1][1], stats[2] + i[1][2]]
                break

    for j in range(1, 64):
        statsother = [0, 0, 0]

        for i in netassayTableByDomain.items():
            for d in domains:

                if (matchDomain(d, i[0], j)):
                    statsother = [statsother[0] + i[1][0], statsother[1] + i[1][1], statsother[2] + i[1][2]]
                    break

        print(str(j)+ ": " + str(statsother[0]/stats[0])+ " "+str(statsother[1]/stats[1])+ " "+str(statsother[2]/stats[2]))



            


