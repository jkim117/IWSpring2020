from sys import argv
import dpkt
import socket
import ipaddress
import matplotlib
import matplotlib.pyplot as plt
import csv

ID_COUNTER = 0 # ensures that the sessionID is unique
clientList = {} # list of sessionLists where key is client ID
#sessionList = {}  list of sessionDicts, key is a sessionID which is given in parse_dns_query
netassayTable = {} # Key is concatentation of serever IP/client IP. Values is a session ID. Allows non-DNS packets to find the appropriate sessionID

allowed_ips = []
banned_ips = []

'''sessionDict = {
    "sequence_num_diff": 0,
    "domain": 'example.com',
    "dns_id": 0,
    "session_id": 0,
    "ts_dns_query": 0,
    "traffic_data": [] # array of traffDicts
}

trafficDict = {
    "sequence_num": 0,
    "ts": 0,
    "flags": 0
}'''

def is_subnet_of(a, b):
    return (b.network_address <= a.network_address and
                    b.broadcast_address >= a.broadcast_address)

def parse_dns_query(ip_packet, ts):
    # Check if it is in the allowed or banned IP lists
    clientIP = socket.inet_ntoa(ip_packet.src)
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

    # Check if this is a never before seen client
    if clientIP in clientList:
        sessionList = clientList[clientIP]
    else:
        sessionList = {}
        clientList[clientIP] = sessionList

    # get domain name
    dns = dpkt.dns.DNS(ip_packet.data.data)
    domain = dns.qd[0].name

    # set up an entry in the sessionList dictionary for this particular session
    global ID_COUNTER
    sessionDict = {
        "domain": domain,
        "dns_id": dns.id,
        "session_id": ID_COUNTER,
        "ts_dns_query": ts,
        "traffic_data": []
    }
    sessionList[dns.id] = sessionDict
    #print(dns.id)
    ID_COUNTER = ID_COUNTER + 1
    clientList[clientIP] = sessionList
    

def parse_dns_response(ip_packet):

    clientIP = socket.inet_ntoa(ip_packet.dst)

    dns = dpkt.dns.DNS(ip_packet.data.data)

    if clientIP not in clientList:
        return
    else:
        sessionList = clientList[clientIP]

    if dns.id not in sessionList:
        return
    
    answers = dns.an
    
    for rr in answers:
        if (rr.type == 1): #DNS.A
            
            serverIP = socket.inet_ntoa(rr.rdata)

            key = clientIP + serverIP

            netassayTable[key] = dns.id


def parse_tcp(ip_packet, ts):
    source = socket.inet_ntoa(ip_packet.src) #server
    dest = socket.inet_ntoa(ip_packet.dst) #client

    if dest not in clientList:
        return
    else:
        sessionList = clientList[dest]

    key = dest + source
    
    #tcp = dpkt.tcp.TCP(ip_packet.data)
    tcp = ip_packet.data
    
    seq_num = tcp.seq
    flags = tcp.flags


    if key in netassayTable:
        dnsID = netassayTable[key]
        trafficDict = {
            "sequence_num": seq_num,
            "ts": ts,
            "flags": flags
        }
        sessionList[dnsID]["traffic_data"].append(trafficDict)
    
    clientList[dest] = sessionList

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
                if (protocol == 17 and ip.data.dport == 53):
                    parse_dns_query(ip, ts)
                elif (protocol == 17 and ip.data.sport == 53):
                    parse_dns_response(ip)
                elif (protocol == 6):
                    parse_tcp(ip, ts)
            except Exception as e:
                print(e)
                continue

    # Make graphs, one per client where x axis is ts and y axis is sequence number, with different colored lines per session
    proceed = input("Number of clients found: " + str(len(clientList))+': Proceed with all?(y/n)\n')
    numClientsToGraph = len(clientList)
    if proceed.lower() != 'y':
        removeClientList = []

        # Create knownlist csv if argument provided
        knownlist = open(argv[2], 'r')
        known_domains = knownlist.read().split()
        knownlist.close()

        for cip in clientList:
            sessionList = clientList[cip]

            keepClient = False
            for s in sessionList.values():
                for d in known_domains:
                    if (matchDomain(d, s['domain'])):
                        keepClient = True
            
            if (keepClient == False):
                removeClientList.append(cip)
            
        for cip in removeClientList:
            clientList.pop(cip)

        proceed2 = input("Number of filtered clients by known domains found: " + str(len(clientList))+': Proceed with all?(y/n)\n')

        if proceed2.lower() != 'y':
            numClientsToGraph = 10

    generateCSV = False
    proceedCSV = input("Generate CSV per client? (y/n)\n")
    if proceedCSV.lower() == 'y':
        generateCSV = True

    clientCounter = 0
    for cip in clientList:
        #print(cip)
        sessionList = clientList[cip]
        fig, ax = plt.subplots()

        for s in sessionList.values():
            timestamps = []
            sequence_numbers = []
            if (len(s['traffic_data']) == 0):
                continue
            for packet in s['traffic_data']:
                timestamps.append(float(packet['ts']) - FIRST_TIMESTAMP)
                sequence_numbers.append(int(packet['sequence_num']))
            
            line, = ax.plot(timestamps, sequence_numbers, marker='.', linestyle='-')
            ax.plot([s['ts_dns_query'] - FIRST_TIMESTAMP], [sequence_numbers[0]], marker='^', color=line.get_color())
            line.set_label('Session: ' + str(s['session_id']) + s['domain'])
            #print(s)

        ax.legend(prop={'size': 5})
        ax.set(xlabel='timestamp', ylabel='sequence number', title='Client: ' + str(cip))
        ax.grid()
        fig.set_size_inches(12,10)
        fig.savefig(cip+'.png')

        if (generateCSV):
            with open(cip+'.csv', 'w') as csvfile:
                w = csv.writer(csvfile)
                w.writerow(['Domain', 'Timestamp of Initial DNS query', 'Sequence Number Range'])

                for s in sessionList.values():
                    if (len(s['traffic_data']) == 0):
                        continue
                    minSeq = int(s['traffic_data'][0]['sequence_num'])
                    maxSeq = int(s['traffic_data'][0]['sequence_num'])
                    
                    for packet in s['traffic_data']:
                        seq = int(packet['sequence_num'])
                        if seq > maxSeq:
                            maxSeq = seq
                        if seq < minSeq:
                            minSeq = seq

                    w.writerow([s['domain'], s['ts_dns_query'] - FIRST_TIMESTAMP, maxSeq - minSeq])

        clientCounter = clientCounter + 1
        if (clientCounter == numClientsToGraph):
            break




            


