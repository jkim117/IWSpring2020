from sys import argv
import dpkt
import socket
import ipaddress
import matplotlib
import matplotlib.pyplot as plt

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
    sessionList[ID_COUNTER] = sessionDict
    ID_COUNTER = ID_COUNTER + 1
    clientList[clientIP] = sessionList
    

def parse_dns_response(ip_packet):

    clientIP = socket.inet_ntoa(ip_packet.dst)

    dns = dpkt.dns.DNS(ip_packet.data.data)
    sessionID = -1

    if clientIP not in clientList:
        return
    else:
        sessionList = clientList[clientIP]

    response_valid = False
    for s in sessionList.values():
        if s['dns_id'] == dns.id:
            response_valid = True
            sessionID = s['session_id']
            break
    if (not response_valid):
        return
    
    answers = dns.an
    
    
    for rr in answers:
        if (rr.type == 1): #DNS.A
            
            serverIP = socket.inet_ntoa(rr.rdata)

            key = clientIP + serverIP

            netassayTable[key] = sessionID
    
    clientList[clientIP] = sessionList


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
        sessionID = netassayTable[key]
        trafficDict = {
            "sequence_num": seq_num,
            "ts": ts,
            "flags": flags
        }
        sessionList[sessionID]["traffic_data"].append(trafficDict)
    
    clientList[dest] = sessionList


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

    with open(argv[1], 'rb') as f:
        pcap_obj = dpkt.pcap.Reader(f)
        #pcap_obj = dpkt.pcapng.Reader(f)

        for ts, buf in pcap_obj:
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
    proceed = input("Number of clients found: " + str(len(clientList))+': Proceed?(y/n)\n')
    if proceed.lower() != 'y':
        exit()


    
    for cip in clientList:
        #print(cip)
        sessionList = clientList[cip]
        fig, ax = plt.subplots()

        for s in sessionList.values():
            timestamps = []
            sequence_numbers = []
            for packet in s['traffic_data']:
                timestamps.append(float(packet['ts']))
                sequence_numbers.append(int(packet['sequence_num']))
            line, = ax.plot(timestamps, sequence_numbers)
            line.set_label('Session: ' + str(s['session_id']) + s['domain'])
            #print(s)

        ax.legend(prop={'size': 5})
        ax.set(xlabel='timestamp', ylabel='sequence number', title='Client: ' + str(cip))
        ax.grid()
        fig.set_size_inches(12,10)
        fig.savefig(cip+'.png')




            


