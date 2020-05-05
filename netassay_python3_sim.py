from sys import argv
import dpkt
import csv
import socket
import ipaddress

# Data structure and global variables
allowed_ips = []
banned_ips = []

knownlistDict = {} # Key is knowlist domain, values are number of dns, number of packets, number of bytes, number missed dns, estimated packets, estimated bytes
known_domains = []

netassayTable = {} # Key is concatentation of serever IP/client IP. Values is a tuple of domain name, num packets, num of bytes
TABLE_SIZE = 2048
usedHash1 = []
usedHash2 = []
usedHash3 = []
usedHash4 = []

def is_subnet_of(a, b):
    return (b.network_address <= a.network_address and b.broadcast_address >= a.broadcast_address)

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
    domain_name = domain.split('.')

    if (len(domain_name) > 4):
        return
    for part in domain_name:
        if (len(part) > 15):
            return

    for d in known_domains:
        if (matchDomain(d, domain)):
            entry = knownlistDict[d]
            knownlistDict[d][0] = knownlistDict[d][0] + 1

            for rr in answers:
                if (rr.type == 1): #DNS.A
                    serverIP = socket.inet_ntoa(rr.rdata)

                    key = clientIP + serverIP
                    hash1 = hash(serverIP + str(11) + clientIP) % TABLE_SIZE
                    hash2 = hash(str(5) + serverIP + str(3) + clientIP)% TABLE_SIZE
                    hash3 = hash(str(0) + serverIP + str(1) + clientIP)% TABLE_SIZE
                    hash4 = hash(str(7) + serverIP + str(12) + clientIP)% TABLE_SIZE
                    
                    if(not hash1 in usedHash1):
                        usedHash1.append(hash1)
                    elif(not hash2 in usedHash2):
                        usedHash2.append(hash2)
                    elif(not hash3 in usedHash3):
                        usedHash3.append(hash3)
                    elif(not hash4 in usedHash4):
                        usedHash4.append(hash4)
                    else:
                        knownlistDict[d][3] = knownlistDict[d][3]+1
                        return

                    
                    # Entry already exists. Hopefully doesn't occur
                    if key in netassayTable:
                        entry = netassayTable[key]
                        if (entry[0] != d):
                            netassayTable[key][0] = d
                    else:
                        # Create new entry
                        netassayTable[key] = [d, 0, 0]

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

    # Create knownlist csv if argument provided
    knownlist = open(argv[2], 'r')
    known_domains = knownlist.read().split()
    knownlist.close()

    for d in known_domains:
        knownlistDict[d] = [0, 0, 0, 0, 0, 0]

    with open(argv[1], 'rb') as f:
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
        knownlistDict[i[0]][1] = knownlistDict[i[0]][1] + i[1]
        knownlistDict[i[0]][2] = knownlistDict[i[0]][2] + i[2]

    for i in knownlistDict.keys():
        num_packets = knownlistDict[i][1]
        num_bytes = knownlistDict[i][2]
        num_missed = knownlistDict[i][3]
        num_dns = knownlistDict[i][0]
        if (num_dns > 0 and num_missed < num_dns):
            knownlistDict[i][4] = num_packets / (1 - (num_missed / num_dns))
            knownlistDict[i][5] = num_bytes / (1 - (num_missed / num_dns))


    with open('sim_results.csv', 'w') as csvfile:
        w = csv.writer(csvfile)
        w.writerow(["Domain", "Number of DNS requests", "Missed DNS requests missed", "Number of Packets", "Number of Bytes", "Estimated Packets", "Estimated Bytes"])

        for i in knownlistDict.items():
            w.writerow([i[0], i[1][0], i[1][3], i[1][1], i[1][2], i[1][4], i[1][5]])

            


