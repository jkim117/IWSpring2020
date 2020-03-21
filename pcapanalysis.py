from sys import argv
import dpkt
import socket

TOTAL_DNS_RESPONSE_COUNT = 0
NUMBER_DOMAINS_LARGE_PART = 0
cnameCountDict = {}
serverIpPrecedenceDict = {}
serverIpUsed = {}
precedenceResultsByPairing = {}
precedenceResultsByPacket = {}
NUM_CLIENTS = 0
NUM_PACKETS = 0

def parse_dns_response(ip_packet):
    global TOTAL_DNS_RESPONSE_COUNT
    global NUMBER_DOMAINS_LARGE_PART
    TOTAL_DNS_RESPONSE_COUNT = TOTAL_DNS_RESPONSE_COUNT + 1

    dns = dpkt.dns.DNS(ip_packet.data.data)
    answers = dns.an

    cname_count = 0
    ipPrecedence = 1

    for rr in answers:
        if (rr.type == 5): #DNS.CNAME
            cname_count = cname_count + 1
        elif (rr.type == 1): #DNS.A
            domain_name = rr.name.split('.')
            for part in domain_name:
                if (len(part) > 15):
                    NUMBER_DOMAINS_LARGE_PART = NUMBER_DOMAINS_LARGE_PART + 1
                    break
            
            clientIP = socket.inet_ntoa(ip_packet.dst)
            serverIP = socket.inet_ntoa(rr.rdata)
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
    key = source + dest

    if (key in serverIpPrecedenceDict):
        global NUM_PACKETS
        NUM_PACKETS = NUM_PACKETS + 1

        ipPrecedence = serverIpPrecedenceDict[key]
        if (not serverIpUsed[key]):
            global NUM_CLIENTS
            NUM_CLIENTS = NUM_CLIENTS + 1
            serverIpUsed[key] = True
            if (ipPrecedence in precedenceResultsByPairing):
                precedenceResultsByPairing[ipPrecedence] = precedenceResultsByPairing[ipPrecedence] + 1
            else:
                precedenceResultsByPairing[ipPrecedence] = 1
        
        if (ipPrecedence in precedenceResultsByPacket):
            precedenceResultsByPacket[ipPrecedence] = precedenceResultsByPacket[ipPrecedence] + 1
        else:
            precedenceResultsByPacket[ipPrecedence] = 1


# parse the command line argument and open the file specified
if __name__ == '__main__':
    if len(argv) != 2:
        print('usage: python pcapanalysis.py capture.pcap')
        exit(-1)

    with open(argv[1], 'rb') as f:
        pcap_obj = dpkt.pcap.Reader(f)
        for ts, buf in pcap_obj:
            eth = dpkt.ethernet.Ethernet(buf)

            if (eth.type != 2048): # If not IPV4
                continue
            ip = eth.data
            protocol = ip.p

            if (protocol == 17 and ip.data.sport == 53):
                parse_dns_response(ip)
            else:
                parse_tcp(ip)

    # Final Stats report
    print("Total Number of DNS Response: " + str(TOTAL_DNS_RESPONSE_COUNT))
    for x in cnameCountDict.items():
        print(str(x[0]) + ' CNAME entries -> ' + str(x[1]) + ' DNS responses')
    print("*********************************************************\n")
    print("Number of domain names with a part larger than 15 characters: " + str(NUMBER_DOMAINS_LARGE_PART))
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
    print("*********************************************************")
