from sys import argv
import dpkt
import csv
import socket
import ipaddress

knownlistDict = {} # Key is knowlist domain, values are number of dns, number of packets, number of bytes, number missed dns, estimated packets, estimated bytes
known_domains = []

netassayTable = {} # Key is concatentation of serever IP/client IP. Values is a tuple of domain name, num packets, num of bytes
TABLE_SIZE = 2048
usedHash1 = {}
usedHash2 = {}
usedHash3 = {}
usedHash4 = {}

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

def parse_client_hello(ip_packet, c_hello, ts):

    # Extract domain name
    for ext in c_hello.extensions:
        e = TLSExtension(ext[0], ext[1])
        if TLSExtensionTypes.get(e.value) == 'server_name':
            domain = str(e.data[5:])[2:-1]
            break
    domain_name = domain.split('.')

    # Parser limitations
    if (len(domain_name) > 4):
        return
    for part in domain_name:
        if (len(part) > 15):
            return

    clientIP = socket.inet_ntoa(ip_packet.src)
    serverIP = socket.inet_ntoa(ip_packet.dst)
    key = clientIP + serverIP

    for d in known_domains:
        if (matchDomain(d, domain)):
            entry = knownlistDict[d]
            knownlistDict[d][0] = knownlistDict[d][0] + 1

            hash1 = hash(serverIP + str(11) + clientIP) % TABLE_SIZE
            hash2 = hash(str(5) + serverIP + str(3) + clientIP)% TABLE_SIZE
            hash3 = hash(str(0) + serverIP + str(1) + clientIP)% TABLE_SIZE
            hash4 = hash(str(7) + serverIP + str(12) + clientIP)% TABLE_SIZE

            if(not hash1 in usedHash1):
                usedHash1[hash1] = [ts, key, domain]
            elif (ts - usedHash1[hash1][0] > 300): # timestamp expires
                usedHash1[hash1] = [ts, key, domain]
            elif(usedHash1[hash1][1] == key and usedHash1[hash1][2] == domain): # update timestamp for existing entry
                usedHash1[hash1] = [ts, key, domain]

            elif(not hash2 in usedHash2):
                usedHash2[hash2] = [ts, key, domain]
            elif (ts - usedHash2[hash2][0] > 300): # timestamp expires
                usedHash2[hash2] = [ts, key, domain]
            elif(usedHash2[hash2][1] == key and usedHash2[hash2][2] == domain): # update timestamp for existing entry
                usedHash2[hash2] = [ts, key, domain]

            elif(not hash3 in usedHash3):
                usedHash3[hash3] = [ts, key, domain]
            elif (ts - usedHash3[hash3][0] > 300): # timestamp expires
                usedHash3[hash3] = [ts, key, domain]
            elif(usedHash3[hash3][1] == key and usedHash3[hash3][2] == domain): # update timestamp for existing entry
                usedHash3[hash3] = [ts, key, domain]

            elif(not hash4 in usedHash4):
                usedHash4[hash4] = [ts, key, domain]
            elif (ts - usedHash4[hash4][0] > 300): # timestamp expires
                usedHash4[hash4] = [ts, key, domain]
            elif(usedHash4[hash4][1] == key and usedHash4[hash4][2] == domain): # update timestamp for existing entry
                usedHash4[hash4] = [ts, key, domain]

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
        

def parse_other(ip_packet, ts):
    source = socket.inet_ntoa(ip_packet.src) #client
    dest = socket.inet_ntoa(ip_packet.dst) #server
    
    key = source + dest
    if key in netassayTable:
        entry = netassayTable[key]
        netassayTable[key] = [entry[0], entry[1] + 1, entry[2] + ip_packet.len]

        hash1 = hash(dest + str(11) + source) % TABLE_SIZE
        hash2 = hash(str(5) + dest + str(3) + source)% TABLE_SIZE
        hash3 = hash(str(0) + dest + str(1) + source)% TABLE_SIZE
        hash4 = hash(str(7) + dest + str(12) + source)% TABLE_SIZE

        if hash1 in usedHash1 and usedHash1[hash1][1] == key:
            usedHash1[hash1][0] = ts
        elif hash2 in usedHash2 and usedHash2[hash2][1] == key:
            usedHash2[hash2][0] = ts
        elif hash3 in usedHash3 and usedHash3[hash3][1] == key:
            usedHash3[hash3][0] = ts
        elif hash4 in usedHash4 and usedHash4[hash4][1] == key:
            usedHash4[hash4][0] = ts
        else:
            print("error in hash storage")
            exit(-1)

    else:
        key = dest + source
        if key in netassayTable:
            entry = netassayTable[key]
            netassayTable[key] = [entry[0], entry[1] + 1, entry[2] + ip_packet.len]

            hash1 = hash(source + str(11) + dest) % TABLE_SIZE
            hash2 = hash(str(5) + source + str(3) + dest)% TABLE_SIZE
            hash3 = hash(str(0) + source + str(1) + dest)% TABLE_SIZE
            hash4 = hash(str(7) + source + str(12) + dest)% TABLE_SIZE

            if hash1 in usedHash1 and usedHash1[hash1][1] == key:
                usedHash1[hash1][0] = ts
            elif hash2 in usedHash2 and usedHash2[hash2][1] == key:
                usedHash2[hash2][0] = ts
            elif hash3 in usedHash3 and usedHash3[hash3][1] == key:
                usedHash3[hash3][0] = ts
            elif hash4 in usedHash4 and usedHash4[hash4][1] == key:
                usedHash4[hash4][0] = ts
            else:
                print("error in hash storage")
                exit(-1)

# parse the command line argument and open the file specified
if __name__ == '__main__':
    if len(argv) != 3:
        print('usage: python netassay_python3.py capture.pcap knownlist.txt')
        exit(-1)

    # Create knownlist
    knownlist = open(argv[2], 'r')
    known_domains = knownlist.read().split()
    knownlist.close()

    for d in known_domains:
        knownlistDict[d] = [0, 0, 0, 0, 0, 0]

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
                            parse_other(ip, ts)
                            continue
                        handshake = dpkt.ssl.TLSHandshake(tls.records[0].data)
                        
                        if (handshake.type != 1):
                            parse_other(ip, ts)
                            continue
                        parse_client_hello(ip, handshake.data, ts)
                    
                    else:
                        parse_other(ip, ts)
                except:
                    parse_other(ip, ts)
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

            


