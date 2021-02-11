from sys import argv
import dpkt
import csv
import socket
import ipaddress
import pickle
import crc16
import numpy as np
import statistics

# Data structure and global variables
allowed_ips = []
banned_ips = []
known_domains = []

knownlistDict = {} # Key is knowlist domain, values are number of dns, number of packets, number of bytes, number missed dns, estimated packets, estimated bytes
netassayTable = {} # Key is concatentation of serever IP/client IP. Value is a knownlist domain name

usedHash1 = {}
usedHash2 = {}
TABLE_SIZE = 0
TIMEOUT = 300

def is_subnet_of(a, b):
    return (b.network_address <= a.network_address and b.broadcast_address >= a.broadcast_address)

def parse_dns_response(ip_packet, ts):
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
    domain_name = domain.split('.')

    # Parser limitations
    if (len(domain_name) > 4):
        return
    for part in domain_name:
        if (len(part) > 15):
            return

    global TIMEOUT
    global TABLE_SIZE

    for d in known_domains:
        if (matchDomain(d, domain)):
            

            for rr in answers:
                if (rr.type != 1):
                    continue
                if (rr.type == 1): #DNS.A
                    entry = knownlistDict[d]
                    knownlistDict[d][0] = knownlistDict[d][0] + 1
                    
                    serverIP = socket.inet_ntoa(rr.rdata)
                    serverIP32 = np.uint32(int.from_bytes(socket.inet_aton(serverIP), byteorder='big'))
                    clientIP32 = np.uint32(int.from_bytes(socket.inet_aton(clientIP), byteorder='big'))
                    salt1 = np.uint32(134140211)
                    salt2 = np.uint32(187182238)

                    key = clientIP + serverIP

                    hash1 = crc16.crc16xmodem(np.uint32(serverIP32 + clientIP32 + salt1)) % TABLE_SIZE
                    hash2 = crc16.crc16xmodem(np.uint32(serverIP32 + clientIP32 + salt2)) % TABLE_SIZE

                    if(not hash1 in usedHash1):
                        usedHash1[hash1] = [ts, key, domain]
                    elif (ts - usedHash1[hash1][0] > TIMEOUT): # timestamp expires
                        netassayTable.pop(usedHash1[hash1][1])
                        usedHash1[hash1] = [ts, key, domain]
                    elif(usedHash1[hash1][1] == key): # update timestamp for existing entry
                        usedHash1[hash1] = [ts, key, domain]

                    elif(not hash2 in usedHash2):
                        usedHash2[hash2] = [ts, key, domain]
                    elif (ts - usedHash2[hash2][0] > TIMEOUT): # timestamp expires
                        netassayTable.pop(usedHash2[hash2][1])
                        usedHash2[hash2] = [ts, key, domain]
                    elif(usedHash2[hash2][1] == key): # update timestamp for existing entry
                        usedHash2[hash2] = [ts, key, domain]

                    else:
                        knownlistDict[d][3] = knownlistDict[d][3]+1
                        return

                    netassayTable[key] = d
                    break
            break
        

def parse_tcp(packet_len, ip_packet, ts):
    source = socket.inet_ntoa(ip_packet['src']) #server
    dest = socket.inet_ntoa(ip_packet['dst']) #client
    global TIMEOUT
    global TABLE_SIZE
    
    key = dest + source
    if key in netassayTable:
        d = netassayTable[key]
        knownlistDict[d][1] = knownlistDict[d][1] + 1
        knownlistDict[d][2] = knownlistDict[d][2] + packet_len

        serverIP32 = np.uint32(int.from_bytes(socket.inet_aton(source), byteorder='big'))
        clientIP32 = np.uint32(int.from_bytes(socket.inet_aton(dest), byteorder='big'))
        salt1 = np.uint32(134140211)
        salt2 = np.uint32(187182238)

        hash1 = crc16.crc16xmodem(np.uint32(serverIP32 + clientIP32 + salt1)) % TABLE_SIZE
        hash2 = crc16.crc16xmodem(np.uint32(serverIP32 + clientIP32 + salt2)) % TABLE_SIZE
        
        if hash1 in usedHash1 and usedHash1[hash1][1] == key:
            usedHash1[hash1][0] = ts
        elif hash2 in usedHash2 and usedHash2[hash2][1] == key:
            usedHash2[hash2][0] = ts
        else:
            print("error in hash storage")
            exit(-1)            


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
        print('usage: python netassay_python3_p4sim.py pickleFile knownlist.txt allowed_dns_dst.txt banned_dns_dst.txt outfilename')
        exit(-1)

    true_60 = {} # key is domain value is [packets, bytes]
    with open('parse60_0000.csv') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if row[0] == 'Domain':
                continue
            true_60[row[0]] = [float(row[3]), float(row[4])]
            
    
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

    f = open(argv[1], 'rb')
    pcap_obj = pickle.load(f)
    f.close()

    outfile = open(argv[5], 'w')

    for i in range(0, 33):
        TABLE_SIZE = 2 ** i
        print(i)
        knownlistDict = {}
        netassayTable = {}
        usedHash1 = {}
        usedHash2 = {}

        for d in known_domains:
            knownlistDict[d] = [0, 0, 0, 0, 0, 0]

        for p in pcap_obj:
            ts = p[0]
            dns_code = p[1]
            ip = p[2]

            # For each packet parse the dns responses
            if (dns_code == -1):
                try:
                    parse_dns_response(ip, ts)
                except Exception as e:
                    
                    continue
            else:
                parse_tcp(dns_code, ip, ts)

        packet_errors = []
        byte_errors = []

        for i in knownlistDict.keys():
            num_packets = knownlistDict[i][1]
            num_bytes = knownlistDict[i][2]
            num_missed = knownlistDict[i][3]
            num_dns = knownlistDict[i][0]
            if (num_dns > 0 and num_missed < num_dns):
                knownlistDict[i][4] = num_packets / (1 - (num_missed / num_dns))
                knownlistDict[i][5] = num_bytes / (1 - (num_missed / num_dns))
                packet_errors.append(abs(true_60[i][0] - knownlistDict[i][4]) / true_60[i][0])
                byte_errors.append(abs(true_60[i][1] - knownlistDict[i][5]) / true_60[i][1])


        packet_error_med = statistics.median(packet_errors)
        byte_error_med = statistics.median(byte_errors)
        total_dns = 0
        total_packets = 0
        total_bytes = 0
        total_dns_missed = 0
        total_est_packets = 0
        total_est_bytes = 0
        for i in knownlistDict.items():
            total_dns += i[1][0]
            total_packets += i[1][1]
            total_bytes += i[1][2]
            total_dns_missed += i[1][3]
            total_est_packets += i[1][4]
            total_est_bytes += i[1][5]
        outfile.write(str(total_dns)+','+str(total_packets)+','+str(total_bytes)+','+str(total_dns_missed)+','+str(total_est_packets)+','+str(total_est_bytes)+','+str(packet_error_med)+','+str(byte_error_med)+'\n')

    outfile.close()




            


