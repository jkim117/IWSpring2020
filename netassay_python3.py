from sys import argv
import dpkt
import csv
import socket
import ipaddress

# Data structure and global variables
TOTAL_DNS_RESPONSE_COUNT = 0
NUMBER_DOMAINS_LARGE_PART = 0
NUMBER_DOMAINS_LARGE_PART_31 = 0

cnameCountDict = {}
serverIpPrecedenceDict = {}
serverIpUsed = {}
precedenceResultsByPairing = {}
precedenceResultsByPacket = {}
numDomainLabels = {}
allowed_ips = []
banned_ips = []
NUM_CLIENTS = 0
NUM_PACKETS = 0

netassayTable = {} # Key is concatentation of serever IP/client IP. Values is a tuple of domain name, num packets, num of bytes
netassayTableByDomain = {} # Key is domain name

def is_subnet_of(a, b):
    return (b.network_address <= a.network_address and
                    b.broadcast_address >= a.broadcast_address)

def parse_dns_response(ip_packet):
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

    # Set up global variabes
    global TOTAL_DNS_RESPONSE_COUNT
    global NUMBER_DOMAINS_LARGE_PART
    global NUMBER_DOMAINS_LARGE_PART_31
    TOTAL_DNS_RESPONSE_COUNT = TOTAL_DNS_RESPONSE_COUNT + 1

    dns = dpkt.dns.DNS(ip_packet.data.data)
    answers = dns.an

    cname_count = 0
    ipPrecedence = 1

    # Extract domain name
    domain = answers[0].name
    domain_name = domain.split('.')

    num_labels = len(domain_name)
    if num_labels in numDomainLabels:
        numDomainLabels[num_labels] = numDomainLabels[num_labels] + 1
    else:
        numDomainLabels[num_labels] = 1

    # Counter number of DNS responses by domain name
    if domain in netassayTableByDomain:
        netassayTableByDomain[domain][0] = netassayTableByDomain[domain][0] + 1
    else:
        netassayTableByDomain[domain] = [1, 0, 0]

    for part in domain_name:
        if (len(part) > 15):
            NUMBER_DOMAINS_LARGE_PART = NUMBER_DOMAINS_LARGE_PART + 1
            break
    for part in domain_name:
        if (len(part) > 31):
            NUMBER_DOMAINS_LARGE_PART_31 = NUMBER_DOMAINS_LARGE_PART_31 + 1
            break

    for rr in answers:
        if (rr.type == 5): #DNS.CNAME
            cname_count = cname_count + 1
        elif (rr.type == 1): #DNS.A
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

            serverIpPrecedenceDict[clientIP + serverIP] = ipPrecedence
            serverIpUsed[clientIP + serverIP] = False
            ipPrecedence = ipPrecedence + 1

    if cname_count in cnameCountDict:
        cnameCountDict[cname_count] = cnameCountDict[cname_count] + 1
    else:
        cnameCountDict[cname_count] = 1
        

def parse_tcp(ip_packet):
    source = socket.inet_ntoa(ip_packet.src) #client
    dest = socket.inet_ntoa(ip_packet.dst) #server
    keyIPUsed = source + dest

    
    key = source + dest
    if key in netassayTable:
        entry = netassayTable[key]
        netassayTable[key] = [entry[0], entry[1] + 1, entry[2] + ip_packet.len]
    else:
        key = dest + source
        if key in netassayTable:
            entry = netassayTable[key]
            netassayTable[key] = [entry[0], entry[1] + 1, entry[2] + ip_packet.len]

    if (keyIPUsed in serverIpPrecedenceDict):
        global NUM_PACKETS
        NUM_PACKETS = NUM_PACKETS + 1

        ipPrecedence = serverIpPrecedenceDict[keyIPUsed]
        if (not serverIpUsed[keyIPUsed]):
            global NUM_CLIENTS
            NUM_CLIENTS = NUM_CLIENTS + 1
            serverIpUsed[keyIPUsed] = True
            if (ipPrecedence in precedenceResultsByPairing):
                precedenceResultsByPairing[ipPrecedence] = precedenceResultsByPairing[ipPrecedence] + 1
            else:
                precedenceResultsByPairing[ipPrecedence] = 1
        
        if (ipPrecedence in precedenceResultsByPacket):
            precedenceResultsByPacket[ipPrecedence] = precedenceResultsByPacket[ipPrecedence] + 1
        else:
            precedenceResultsByPacket[ipPrecedence] = 1

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
        print('usage: python netassay_python3.py capture.pcap knownlist.txt allowed_dns_dst.txt banned_dns_dst.txt')
        exit(-1)
    
    # Parse allowed IP and banned IP files
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
        try:
            pcap_obj = dpkt.pcap.Reader(f)
        except:
            pcap_obj = dpkt.pcapng.Reader(f)

        for ts, buf in pcap_obj:
            eth = dpkt.ethernet.Ethernet(buf)

            if (eth.type != 2048): # If not IPV4
                continue
            ip = eth.data
            protocol = ip.p

            # For each packet parse the dns responses
            try:
                if (protocol == 17 and ip.data.sport == 53):
                    parse_dns_response(ip)
                else:
                    parse_tcp(ip)
            except:
                continue

    # Final Stats report
    print("Total Number of DNS Response: " + str(TOTAL_DNS_RESPONSE_COUNT))
    for x in cnameCountDict.items():
        print(str(x[0]) + ' CNAME entries -> ' + str(x[1]) + ' DNS responses')
    print("*********************************************************\n")
    print("Number of domain names with a part larger than 15 characters: " + str(NUMBER_DOMAINS_LARGE_PART))
    print("Number of domain names with a part larger than 31 characters: " + str(NUMBER_DOMAINS_LARGE_PART_31))
    print("*********************************************************\n")

    print("Total number of individual clients: " + str(NUM_CLIENTS))
    for x in precedenceResultsByPairing.items():
        print("Number of clients that used IP address in DNS response of precedence: " + str(x[0]) + ": " + str(x[1]))
    if (1 in precedenceResultsByPairing):
        print("Percentage of clients that used the first IP address from the DNS response: " + str(precedenceResultsByPairing[1] / float(NUM_CLIENTS)))
    else:
        print("Percentage of clients that used the first IP address from the DNS response: 0")
    print("*********************************************************\n")

    print("Total number of packets: " + str(NUM_PACKETS))
    for x in precedenceResultsByPacket.items():
        print("Number of packets from clients that used IP address in DNS response of precedence: " + str(x[0]) + ": " + str(x[1]))
    if (1 in precedenceResultsByPacket):
        print("Percentage of packets that used the first IP address from the DNS response: " + str(precedenceResultsByPacket[1] / float(NUM_PACKETS)))
    else:
        print("Percentage of packets that used the first IP address from the DNS response: 0")
    print("*********************************************************\n")

    print("Number of labels in domains:")
    for x in numDomainLabels.items():
        print("Domains with " + str(x[0]) + " labels: " + str(x[1]))
    print("*********************************************************")


    for i in netassayTable.values():
        netassayTableByDomain[i[0]][1] = netassayTableByDomain[i[0]][1] + i[1]
        netassayTableByDomain[i[0]][2] = netassayTableByDomain[i[0]][2] + i[2]


    with open('allresults.csv', 'w') as csvfile:
        w = csv.writer(csvfile)
        w.writerow(["Domain", "Number of DNS requests", "Number of Packets", "Number of Bytes"])

        for i in netassayTableByDomain.items():
            w.writerow([i[0], i[1][0], i[1][1], i[1][2]])

    # Create knownlist csv if argument provided
    knownlist = open(argv[2], 'r')
    domains = knownlist.read().split()
    knownlist.close()

    knownlistDict = {} # Key is knowlist domain, values are number of dns, number of packets, number of bytes
    for d in domains:
        knownlistDict[d] = [0, 0, 0]

    for i in netassayTableByDomain.items():
        for d in domains:
            if (matchDomain(d, i[0])):
                entry = knownlistDict[d]
                knownlistDict[d] = [entry[0] + i[1][0], entry[1] + i[1][1], entry[2] + i[1][2]]
                break
    
    with open('knownlistresults.csv', 'w') as csvfile:
        w = csv.writer(csvfile)
        w.writerow(["Domain", "Number of DNS requests", "Number of Packets", "Number of Bytes"])

        for i in knownlistDict.items():
            w.writerow([i[0], i[1][0], i[1][1], i[1][2]])

            


