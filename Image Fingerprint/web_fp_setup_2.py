from sys import argv
import dpkt
import socket
import ipaddress
import matplotlib
import matplotlib.pyplot as plt
import csv
import json

netassayTable = {} # Key is concatentation of serever IP/client IP. Values is a session ID. Allows non-DNS packets to find the appropriate sessionID
dnsTimestampTable = {}

allowed_ips = []
banned_ips = []

def is_subnet_of(a, b):
    return (b.network_address <= a.network_address and
                    b.broadcast_address >= a.broadcast_address)
    

def parse_dns_response(ip_packet, ts):

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

    dnsTimestampTable[ts] = domain
    
    answers = dns.an
    
    for rr in answers:
        if (rr.type == 1): #DNS.A
            
            serverIP = socket.inet_ntoa(rr.rdata)

            # Create an entry in the netassayTable with list of domains and a list of sessions (distinguised by port number)
            # The key is the clientIP and serverIP. If the client makes multiple dns requests to the same domain or
            # if the client makes a request to a domain with the same IP address, all those domains will be added to this entry
            key = clientIP + '/' + serverIP
            if key not in netassayTable:
                netassayTable[key] = {"domain": [domain], "sessions": {}}
            else:
                netassayTable[key]['domain'].append(domain)
    

def parse_tcp(ip_packet, ts):
    source = socket.inet_ntoa(ip_packet.src) #server
    dest = socket.inet_ntoa(ip_packet.dst) #client

    key = dest + '/' + source

    # If client and source IP are not in the netassayTable (never was a DNS request), then ignore
    if key not in netassayTable:
        return
    
    entry = netassayTable[key]
    tcp = ip_packet.data
    seq_num = tcp.seq
    client_port = tcp.dport

    # Check if the client port is in the netassayTable entry
    if client_port in entry["sessions"]:

        if seq_num < entry['sessions'][client_port][1]:
            print('Error: New Sequence Number unexpectedly smaller for session')
            print('new: ' + str(seq_num))
            print('old: ' + str(entry['sessions'][client_port][1]))
            print(client_port)
            print(source)
            print(dest)
        else:
            netassayTable[key]['sessions'][client_port][1] = seq_num # Mark the sequence number

    # If client port is not in the netassayTable entry, this is a new session. Create a new entry, keyed by the port. Add the initial sequence number to the entry
    else:
        netassayTable[key]["sessions"][client_port] = [seq_num, -1, ts]


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
        print('usage: python netassay_python3.py capture.pcap known_domains.txt allowed_dns_dst.txt banned_dns_dst.txt')
        exit(-1)
    
    # Parse allowed IP and banned IP files
    '''allowed_ip_file = open(argv[3], 'r')
    allowed_ip_list = allowed_ip_file.read().split()
    allowed_ip_file.close()
    for ip in allowed_ip_list:
        allowed_ips.append(ipaddress.ip_network(ip))

    banned_ip_file = open(argv[4], 'r')
    banned_ip_list = banned_ip_file.read().split()
    banned_ip_file.close()
    for ip in banned_ip_list:
        banned_ips.append(ipaddress.ip_network(ip))'''

    known_domains = []

    known_domains_file = open(argv[2], 'r')
    known_list = known_domains_file.read().split()
    known_domains_file.close()
    for d in known_list:
        known_domains.append(d)
    with open(argv[1], 'rb') as f:
        #pcap_obj = dpkt.pcap.Reader(f)
        pcap_obj = dpkt.pcapng.Reader(f)

        for ts, buf in pcap_obj:
            eth = dpkt.ethernet.Ethernet(buf)

            if (eth.type != 2048): # If not IPV4
                continue
            ip = eth.data
            protocol = ip.p

            # Parse packets
            try:
                if (protocol == 17 and ip.data.sport == 53):
                    parse_dns_response(ip, ts)
                elif (protocol == 6):
                    parse_tcp(ip, ts)
            except Exception as e:
                print(e)
                continue

    with open(argv[1].split('.')[0] + '-dns_ts.csv', 'w') as csvfile:
        w = csv.writer(csvfile)
        w.writerow(['Timestamp, DNS Domain Queried'])
        for key in dnsTimestampTable:
            w.writerow([key, dnsTimestampTable[key]])

    with open(argv[1].split('.')[0] + '.csv', 'w') as csvfile:
        w = csv.writer(csvfile)
        w.writerow(['Client IP', 'Server IP', 'Client Port', 'Initial Timestamp', 'Sequence Diff', 'Possible Domains'])

        for key in netassayTable:
            splitkey = key.split('/')
            cip = splitkey[0]
            sip = splitkey[1]

            possibledomains = ''
            skip = False
            for d in netassayTable[key]['domain']:
                for kd in known_domains:
                    if matchDomain(kd, d):
                        skip = False
                possibledomains = possibledomains + d + '/'
            
            #if (skip):
                #continue
            
            sessions = netassayTable[key]['sessions']

            for port in sessions:
                timestamp = sessions[port][2]
                seqdiff = sessions[port][1] - sessions[port][0]
                if sessions[port][1] == -1:
                    seqdiff = 0

                w.writerow([cip, sip, port, timestamp, seqdiff, possibledomains])






