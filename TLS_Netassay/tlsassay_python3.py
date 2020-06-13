from sys import argv
import dpkt
import csv
import socket
import ipaddress

# Data structure and global variables
TOTAL_CLIENT_HELLO_COUNT = 0
NUMBER_DOMAINS_LARGE_PART = 0
NUMBER_DOMAINS_LARGE_PART_31 = 0

numDomainLabels = {}

netassayTable = {} # Key is concatentation of serever IP/client IP. Values is a tuple of domain name, num packets, num of bytes
netassayTableByDomain = {} # Key is domain name

TLSExtensionTypes = {
    0: 'server_name',
    1: 'max_fragment_length',
    2: 'client_certificate_url',
    3: 'trusted_ca_keys',
    4: 'truncated_hmac',
    5: 'status_request',
    6: 'user_mapping',
    7: 'client_authz',
    8: 'server_authz',
    9: 'cert_type',
    10: 'elliptic_curves',
    11: 'ec_point_formats',
    12: 'srp',
    13: 'signature_algorithms',
    14: 'use_srtp',
    15: 'heartbeat',
    35: 'session_tickets',
    13172: 'next_protocol_negotiation',
    65281: 'renegotiation_info',
}

class TLSExtension(object):
    def __init__(self, ext_number, data):
        self.data = data
        self.value = ext_number

    @property
    def name(self):
        return TLSExtensionTypes.get(self.value, 'unknown')

def parse_client_hello(ip_packet, c_hello):
    # Set up global variabes
    global TOTAL_CLIENT_HELLO_COUNT
    global NUMBER_DOMAINS_LARGE_PART
    global NUMBER_DOMAINS_LARGE_PART_31
    TOTAL_CLIENT_HELLO_COUNT = TOTAL_CLIENT_HELLO_COUNT + 1

    # Extract domain name
    for ext in c_hello.extensions:
        e = TLSExtension(ext[0], ext[1])
        if TLSExtensionTypes.get(e.value) == 'server_name':
            domain = str(e.data[5:])[2:-1]
            break
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

    clientIP = socket.inet_ntoa(ip_packet.src)
    serverIP = socket.inet_ntoa(ip_packet.dst)
    key = clientIP + serverIP

    # Entry already exists. Hopefully doesn't occur
    if key in netassayTable:
        entry = netassayTable[key]
        if (entry[0] != domain):
            netassayTable[key][0] = domain
    else:
        # Create new entry
        netassayTable[key] = [domain, 0, 0]
        

def parse_other(ip_packet):
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
    if len(argv) != 3:
        print('usage: python netassay_python3.py capture.pcap knownlist.txt')
        exit(-1)

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
                try:
                    if (protocol == 6):
                        tcp = ip.data
                        tls = dpkt.ssl.TLS(tcp.data)
                        if (len(tls.records) < 1 or tls.type != 22):
                            parse_other(ip)
                            continue
                        handshake = dpkt.ssl.TLSHandshake(tls.records[0].data)
                        
                        if (handshake.type != 1):
                            parse_other(ip)
                            continue
                        parse_client_hello(ip, handshake.data)
                    
                    else:
                        parse_other(ip)
                except:
                    parse_other(ip)
            except:
                continue

    # Final Stats report
    print("Total Number of TLS CLient Hellos: " + str(TOTAL_CLIENT_HELLO_COUNT))
    
    print("*********************************************************\n")
    print("Number of domain names with a part larger than 15 characters: " + str(NUMBER_DOMAINS_LARGE_PART))
    print("Number of domain names with a part larger than 31 characters: " + str(NUMBER_DOMAINS_LARGE_PART_31))
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

            


