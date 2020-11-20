from sys import argv
import dpkt
import csv
import socket
import ipaddress
import pickle

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

DETECTION_THRESH = 0.25
rulesList = {}

netassayTable = {} # Key is concatentation of serever IP/client IP. Values is domain name
clientTable = {}

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

    dns = dpkt.dns.DNS(ip_packet.data.data)
    answers = dns.an

    domain = answers[0].name

    for d in known_domains:
        if (matchDomain(d, domain)):
            
            for rr in answers:
                if (rr.type == 1):
                    serverIP = socket.inet_ntoa(rr.rdata)

                    key = clientIP + serverIP
                    # Entry already exists. Hopefully doesn't occur
                    if key in netassayTable:
                        entry = netassayTable[key]
                        if (entry != domain):
                            netassayTable[key] = domain
                    else:
                        # Create new entry
                        netassayTable[key] = domain

            break
        

def parse_tcp(packet_len, ip_packet, ts):
    source = socket.inet_ntoa(ip_packet['src']) #client
    dest = socket.inet_ntoa(ip_packet['dst']) #server
    port = float(ip_packet['src_port'])
    
    key = dest + source # We just want to count traffic coming from the server
    if key in netassayTable:
        domain_name = netassayTable[key]
        netassayTable.pop(key)

        if dest in clientTable:
            client_ts = clientTable[dest][1]
            if ts - client_ts >= 300000000: # 5 minutes
                clientTable[dest] = [[[domain_name, port]], ts]
            else:
                clientTable[dest][0].append([domain_name, port])
                clientTable[dest][1] = ts
        else:
            clientTable[dest] = [[[domain_name, port]], ts]

        detection_occur = False
        # check rules
        for k in rulesList.keys():
            num_matches = 0

            num_domains_in_rule = len(rulesList[k])
            for d in rulesList[k]:
                rule_domain = d[0]
                rule_port= float(d[1])

                for c in clientTable[dest][0]:
                    client_domain = c[0]
                    client_port = c[1]
                    if (matchDomain(rule_domain, client_domain) and client_port == rule_port):
                        num_matches += 1
                        break
            if (num_matches >= DETECTION_THRESH * num_domains_in_rule):
                print(dest, k, ts)
                detection_occur = True
            
        if(detection_occur):
            clientTable.pop(dest)
                    


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
        print('usage: python netassay_python3.py pickleFile knownlist.txt allowed_dns_dst.txt banned_dns_dst.txt rules')
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

    # Create knownlist
    knownlist = open(argv[2], 'r')
    known_domains = knownlist.read().split()
    knownlist.close()

    # create rules list
    rulesFile = open(argv[5], 'rb')
    rulesList = pickle.load(rulesFile)
    rulesFile.close()

    f = open(argv[1], 'rb')
    pcap_obj = pickle.load(f)
    f.close()

    for p in pcap_obj:
        ts = p[0]
        dns_code = p[1]
        ip = p[2]

        # For each packet parse the dns responses
        #try:
        if (dns_code == -1):
            try:
                parse_dns_response(ip)
            except:
                continue
        else:
            parse_tcp(dns_code, ip, ts)
        

            


