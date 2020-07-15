from sys import argv
import dpkt
import socket
import ipaddress
import matplotlib
import matplotlib.pyplot as plt
import csv
import json

netassayTable = {} # Key is concatentation of serever IP/client IP. Values is a session ID. Allows non-DNS packets to find the appropriate sessionID
client_webpage_table = {} # Key is CIP, value is domain and seq num diff

allowed_ips = []
banned_ips = []

known_domains = []
requested_domains = {}


def is_subnet_of(a, b):
    return (b.network_address <= a.network_address and
                    b.broadcast_address >= a.broadcast_address)
    

def parse_dns_response(ip_packet):

    clientIP = socket.inet_ntoa(ip_packet.dst)
    '''cip_object = ipaddress.ip_network(clientIP)
    allowed = False
    for ip in allowed_ips:
        if is_subnet_of(cip_object, ip):
            allowed = True
            break
    if (not allowed):
        return
    for ip in banned_ips:
        if is_subnet_of(cip_object, ip):
            return'''

    # get domain name
    dns = dpkt.dns.DNS(ip_packet.data.data)
    domain = dns.qd[0].name

    match = ''

    # Check that domain is a known domain
    for d in known_domains:
        if(matchDomain(d, domain)):
            match = d
    if (match == ''):
        return

    # Mark this domain as visited by this client
    if clientIP in requested_domains:
        requested_domains[clientIP].append(match)
    else:
        requested_domains[clientIP] = [match]
    
    answers = dns.an
    
    for rr in answers:
        if (rr.type == 1): #DNS.A
            
            serverIP = socket.inet_ntoa(rr.rdata)

            # Create an entry in the netassayTable with domain and a list of sessions (distinguised by port number)
            # The key is the clientIP and serverIP. If the client makes multiple dns requests to the same domain or
            # if the client makes a request to a domain with the same IP address, the entry will not change (the domain name will stay with the original domain requested)
            key = clientIP + serverIP
            if key not in netassayTable:
                netassayTable[key] = {"domain": match, "sessions": {}}
    

def parse_tcp(ip_packet, ts):
    source = socket.inet_ntoa(ip_packet.src) #server
    dest = socket.inet_ntoa(ip_packet.dst) #client

    key = dest + source

    '''if not (ip_packet.data.flags & 1 == 0):
        print('hiiiii')
        print(source)'''

    # If client and source IP are not in the netassayTable (never was a DNS request), then ignore
    if key not in netassayTable:
        return
    
    entry = netassayTable[key]
    tcp = ip_packet.data
    seq_num = tcp.seq
    flags = tcp.flags
    client_port = tcp.dport

    # Check if the client port is in the netassayTable entry
    if client_port in entry["sessions"]:

        # If the FIN flag is marked
        if not (flags & 1 == 0):
            netassayTable[key]['sessions'][client_port][1] = seq_num # Mark the final sequence number

            # If client is already in the client_webpage_table
            if dest in client_webpage_table:

                # If this particular domain is already in the client's dict in the client_webpage_table -> Add the new sequence number diff to the existing entry
                if netassayTable[key]["domain"] in client_webpage_table[dest]:
                    client_webpage_table[dest][netassayTable[key]["domain"]] = client_webpage_table[dest][netassayTable[key]["domain"]] + seq_num - netassayTable[key]['sessions'][client_port][0]
                else:
                    # Create the entry for this domain
                    client_webpage_table[dest][netassayTable[key]["domain"]] = seq_num - netassayTable[key]['sessions'][client_port][0]
            
            # If client is not in the client_webpage_table: create an entry that is a dictionary with the key being the domain and the value being the sequence number diff
            else:
                client_webpage_table[dest] = {netassayTable[key]["domain"]:seq_num - netassayTable[key]['sessions'][client_port][0]}

    # If client port is not in the netassayTable entry, this is a new session. Create a new entry, keyed by the port. Add the initial sequence number to the entry
    else:
        netassayTable[key]["sessions"][client_port] = [seq_num, -1]


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
        print('usage: python netassay_python3.py capture.pcap webpages.json allowed_dns_dst.txt banned_dns_dst.txt')
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

    webpage_list = []
    # Extract webpage domains
    with open(argv[2]) as json_file:
        data = json.load(json_file)
        webpage_list = data["webpages"]
        for w in webpage_list:
            #print(w["webpage_name"])
            for d in w['domains']:
                for i in range(1, d[0] + 1):
                    known_domains.append(d[i])
                #print(d[0])
                #print(d[1])

    FIRST_TIMESTAMP = -1
    with open(argv[1], 'rb') as f:
        #pcap_obj = dpkt.pcap.Reader(f)
        pcap_obj = dpkt.pcapng.Reader(f)

        for ts, buf in pcap_obj:
            if (FIRST_TIMESTAMP == -1):
                FIRST_TIMESTAMP = ts
            #print(ts - FIRST_TIMESTAMP)
            eth = dpkt.ethernet.Ethernet(buf)

            if (eth.type != 2048): # If not IPV4
                continue
            ip = eth.data
            protocol = ip.p

            # Parse packets
            try:
                if (protocol == 17 and ip.data.sport == 53):
                    parse_dns_response(ip)
                elif (protocol == 6):
                    parse_tcp(ip, ts)
            except Exception as e:
                print(e)
                continue

    for w in webpage_list:
        for c in client_webpage_table:

            match_webpage = True
            for d in w['domains']:

                accumulated_bytes = 0

                for i in range(1, d[0] + 1):
                    if d[i] not in requested_domains[c]:
                        match_webpage = False
                        break

                    if d[i] in client_webpage_table[c]:
                        accumulated_bytes = accumulated_bytes + client_webpage_table[c][d[i]]

                #print(str(d) + ' ' + str(accumulated_bytes))
                expected_bytes = d[d[0] + 1]
                if abs((accumulated_bytes - expected_bytes) / expected_bytes) > 1:
                    match_webpage = False
            
            if (match_webpage):
                print('Client ' + c + ' matched to ' + w['webpage_name'])

    full_report = input('Genereate full client report? (y/n)\n')
    if (full_report.lower() == 'y'):
        for c in client_webpage_table:
            print(c + ': ' + str(client_webpage_table[c]))






