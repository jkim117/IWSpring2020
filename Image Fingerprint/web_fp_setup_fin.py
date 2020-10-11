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
    
    answers = dns.an
    
    for rr in answers:
        if (rr.type == 1): #DNS.A
            
            serverIP = socket.inet_ntoa(rr.rdata)

            # Create an entry in the netassayTable with list of domains and a list of sessions (distinguised by port number)
            # The key is the clientIP and serverIP. If the client makes multiple dns requests to the same domain or
            # if the client makes a request to a domain with the same IP address, all those domains will be added to this entry
            key = clientIP + serverIP
            if key not in netassayTable:
                netassayTable[key] = {"domain": [domain], "sessions": {}}
            else:
                netassayTable[key]['domain'].append(domain)
    

def parse_tcp(ip_packet, ts):
    source = socket.inet_ntoa(ip_packet.src) #server
    dest = socket.inet_ntoa(ip_packet.dst) #client

    key = dest + source

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

                # If this particular server address is already in the client's dict in the client_webpage_table -> Add the new sequence number diff to the existing entry
                if source in client_webpage_table[dest]:
                    client_webpage_table[dest][source] = client_webpage_table[dest][source] + seq_num - netassayTable[key]['sessions'][client_port][0]
                else:
                    # Create the entry for this domain
                    client_webpage_table[dest][source] = seq_num - netassayTable[key]['sessions'][client_port][0]
            
            # If client is not in the client_webpage_table: create an entry that is a dictionary with the key being the server address and the value being the sequence number diff
            else:
                client_webpage_table[dest] = {source:seq_num - netassayTable[key]['sessions'][client_port][0]}

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
    if len(argv) != 4:
        print('usage: python netassay_python3.py capture.pcap allowed_dns_dst.txt banned_dns_dst.txt')
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


    client_output_dict = {}
    for c in client_webpage_table:

        domains_list = []

        for s in client_webpage_table[c]:
            total_bytes = client_webpage_table[c][s]

            key = c + s

            domain_group = [len(netassayTable[key]['domain'])]

            for d in netassayTable[key]['domain']:
                domain_group.append(d)
            
            domain_group.append(total_bytes)
            domains_list.append(domain_group)

        client_output_dict[c] = domains_list


    #with open('webv2_clients.json', 'w') as outfile:
        #json.dump(client_output_dict, outfile)
    
    for c in client_output_dict:
        with open(c+'fin.csv', 'w') as csvfile:
            w = csv.writer(csvfile)
            w.writerow(['Domains', 'Sequence Number Diff'])

            for site in client_output_dict[c]:

                domainString = ''
                for i in range(1, site[0] + 1):
                    if i < site[0]:
                        domainString = domainString + site[i] + '/'
                    else:
                        domainString = domainString + site[i]
                
                w.writerow([domainString, site[site[0] + 1]])






