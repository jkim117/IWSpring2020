from sys import argv
import dpkt
import csv
import socket
import ipaddress
import pickle
import crc16
import numpy as np

# Data structure and global variables
allowed_ips = []
banned_ips = []
known_domains = []

knownlistDict = {} # Key is knowlist domain, values are number of dns, number of packets, number of bytes, number missed dns, estimated packets, estimated bytes
netassayTable = {} # Key is concatentation of serever IP/client IP. Value is a knownlist domain name

usedHash1 = {}
usedHash2 = {}
usedHash3 = {}
usedHash4 = {}
usedHash5 = {}
usedHash6 = {}
usedHash7 = {}
usedHash8 = {}
usedHash9 = {}
usedHash10 = {}

TABLE_SIZE = 131072
TIMEOUT = 300

def is_subnet_of(a, b):
    return (b.network_address <= a.network_address and b.broadcast_address >= a.broadcast_address)

def parse_dns_response(ip_packet, ts, i):
    global TIMEOUT
    global TABLE_SIZE

    modulo = int(TABLE_SIZE / i)
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
                    salt3 = np.uint32(187238)
                    salt4 = np.uint32(1853238)
                    salt5 = np.uint32(1828)
                    salt6 = np.uint32(12238)
                    salt7 = np.uint32(72134)
                    salt8 = np.uint32(152428)
                    salt9 = np.uint32(164314534)
                    salt10 = np.uint32(223823)

                    key = clientIP + serverIP

                    hash1 = crc16.crc16xmodem(np.uint32(serverIP32 + clientIP32 + salt1)) % modulo
                    hash2 = crc16.crc16xmodem(np.uint32(serverIP32 + clientIP32 + salt2)) % modulo
                    hash3 = crc16.crc16xmodem(np.uint32(serverIP32 + clientIP32 + salt3)) % modulo
                    hash4 = crc16.crc16xmodem(np.uint32(serverIP32 + clientIP32 + salt4)) % modulo
                    hash5 = crc16.crc16xmodem(np.uint32(serverIP32 + clientIP32 + salt5)) % modulo
                    hash6 = crc16.crc16xmodem(np.uint32(serverIP32 + clientIP32 + salt6)) % modulo
                    hash7 = crc16.crc16xmodem(np.uint32(serverIP32 + clientIP32 + salt7)) % modulo
                    hash8 = crc16.crc16xmodem(np.uint32(serverIP32 + clientIP32 + salt8)) % modulo
                    hash9 = crc16.crc16xmodem(np.uint32(serverIP32 + clientIP32 + salt9)) % modulo
                    hash10 = crc16.crc16xmodem(np.uint32(serverIP32 + clientIP32 + salt10)) % modulo

                    if(not hash1 in usedHash1):
                        usedHash1[hash1] = [ts, key, domain]
                    elif (ts - usedHash1[hash1][0] > TIMEOUT): # timestamp expires
                        netassayTable.pop(usedHash1[hash1][1])
                        usedHash1[hash1] = [ts, key, domain]
                    elif(usedHash1[hash1][1] == key): # update timestamp for existing entry
                        usedHash1[hash1] = [ts, key, domain]
                    elif(i < 2):
                        knownlistDict[d][3] = knownlistDict[d][3]+1
                        return

                    elif(not hash2 in usedHash2):
                        usedHash2[hash2] = [ts, key, domain]
                    elif (ts - usedHash2[hash2][0] > TIMEOUT): # timestamp expires
                        netassayTable.pop(usedHash2[hash2][1])
                        usedHash2[hash2] = [ts, key, domain]
                    elif(usedHash2[hash2][1] == key): # update timestamp for existing entry
                        usedHash2[hash2] = [ts, key, domain]
                    elif(i < 3):
                        knownlistDict[d][3] = knownlistDict[d][3]+1
                        return
                    
                    elif(not hash3 in usedHash3):
                        usedHash3[hash3] = [ts, key, domain]
                    elif (ts - usedHash3[hash3][0] > TIMEOUT): # timestamp expires
                        netassayTable.pop(usedHash3[hash3][1])
                        usedHash3[hash3] = [ts, key, domain]
                    elif(usedHash3[hash3][1] == key): # update timestamp for existing entry
                        usedHash3[hash3] = [ts, key, domain]
                    elif(i < 4):
                        knownlistDict[d][3] = knownlistDict[d][3]+1
                        return

                    elif(not hash4 in usedHash4):
                        usedHash4[hash4] = [ts, key, domain]
                    elif (ts - usedHash4[hash4][0] > TIMEOUT): # timestamp expires
                        netassayTable.pop(usedHash4[hash4][1])
                        usedHash4[hash4] = [ts, key, domain]
                    elif(usedHash4[hash4][1] == key): # update timestamp for existing entry
                        usedHash4[hash4] = [ts, key, domain]
                    elif(i < 5):
                        knownlistDict[d][3] = knownlistDict[d][3]+1
                        return

                    elif(not hash5 in usedHash5):
                        usedHash5[hash5] = [ts, key, domain]
                    elif (ts - usedHash5[hash5][0] > TIMEOUT): # timestamp expires
                        netassayTable.pop(usedHash5[hash5][1])
                        usedHash5[hash5] = [ts, key, domain]
                    elif(usedHash5[hash5][1] == key): # update timestamp for existing entry
                        usedHash5[hash5] = [ts, key, domain]
                    elif(i < 6):
                        knownlistDict[d][3] = knownlistDict[d][3]+1
                        return

                    elif(not hash6 in usedHash6):
                        usedHash6[hash6] = [ts, key, domain]
                    elif (ts - usedHash6[hash6][0] > TIMEOUT): # timestamp expires
                        netassayTable.pop(usedHash6[hash6][1])
                        usedHash6[hash6] = [ts, key, domain]
                    elif(usedHash6[hash6][1] == key): # update timestamp for existing entry
                        usedHash6[hash6] = [ts, key, domain]
                    elif(i < 7):
                        knownlistDict[d][3] = knownlistDict[d][3]+1
                        return

                    elif(not hash7 in usedHash7):
                        usedHash7[hash7] = [ts, key, domain]
                    elif (ts - usedHash7[hash7][0] > TIMEOUT): # timestamp expires
                        netassayTable.pop(usedHash7[hash7][1])
                        usedHash7[hash7] = [ts, key, domain]
                    elif(usedHash7[hash7][1] == key): # update timestamp for existing entry
                        usedHash7[hash7] = [ts, key, domain]
                    elif(i < 8):
                        knownlistDict[d][3] = knownlistDict[d][3]+1
                        return

                    elif(not hash8 in usedHash8):
                        usedHash8[hash8] = [ts, key, domain]
                    elif (ts - usedHash8[hash8][0] > TIMEOUT): # timestamp expires
                        netassayTable.pop(usedHash8[hash8][1])
                        usedHash8[hash8] = [ts, key, domain]
                    elif(usedHash8[hash8][1] == key): # update timestamp for existing entry
                        usedHash8[hash8] = [ts, key, domain]
                    elif(i < 9):
                        knownlistDict[d][3] = knownlistDict[d][3]+1
                        return

                    elif(not hash9 in usedHash9):
                        usedHash9[hash9] = [ts, key, domain]
                    elif (ts - usedHash9[hash9][0] > TIMEOUT): # timestamp expires
                        netassayTable.pop(usedHash9[hash9][1])
                        usedHash9[hash9] = [ts, key, domain]
                    elif(usedHash9[hash9][1] == key): # update timestamp for existing entry
                        usedHash9[hash9] = [ts, key, domain]
                    elif(i < 10):
                        knownlistDict[d][3] = knownlistDict[d][3]+1
                        return

                    elif(not hash10 in usedHash10):
                        usedHash10[hash10] = [ts, key, domain]
                    elif (ts - usedHash10[hash10][0] > TIMEOUT): # timestamp expires
                        netassayTable.pop(usedHash10[hash10][1])
                        usedHash10[hash10] = [ts, key, domain]
                    elif(usedHash10[hash10][1] == key): # update timestamp for existing entry
                        usedHash10[hash10] = [ts, key, domain]
                    else:
                        knownlistDict[d][3] = knownlistDict[d][3]+1
                        return

                    netassayTable[key] = d
                    break
            break
        

def parse_tcp(packet_len, ip_packet, ts, i):
    global TIMEOUT
    global TABLE_SIZE
    modulo = int(TABLE_SIZE / i)

    source = socket.inet_ntoa(ip_packet['src']) #server
    dest = socket.inet_ntoa(ip_packet['dst']) #client
    
    key = dest + source
    if key in netassayTable:
        d = netassayTable[key]
        knownlistDict[d][1] = knownlistDict[d][1] + 1
        knownlistDict[d][2] = knownlistDict[d][2] + packet_len

        serverIP32 = np.uint32(int.from_bytes(socket.inet_aton(source), byteorder='big'))
        clientIP32 = np.uint32(int.from_bytes(socket.inet_aton(dest), byteorder='big'))
        salt1 = np.uint32(134140211)
        salt2 = np.uint32(187182238)
        salt3 = np.uint32(187238)
        salt4 = np.uint32(1853238)
        salt5 = np.uint32(1828)
        salt6 = np.uint32(12238)
        salt7 = np.uint32(72134)
        salt8 = np.uint32(152428)
        salt9 = np.uint32(164314534)
        salt10 = np.uint32(223823)

        hash1 = crc16.crc16xmodem(np.uint32(serverIP32 + clientIP32 + salt1)) % modulo
        hash2 = crc16.crc16xmodem(np.uint32(serverIP32 + clientIP32 + salt2)) % modulo
        hash3 = crc16.crc16xmodem(np.uint32(serverIP32 + clientIP32 + salt3)) % modulo
        hash4 = crc16.crc16xmodem(np.uint32(serverIP32 + clientIP32 + salt4)) % modulo
        hash5 = crc16.crc16xmodem(np.uint32(serverIP32 + clientIP32 + salt5)) % modulo
        hash6 = crc16.crc16xmodem(np.uint32(serverIP32 + clientIP32 + salt6)) % modulo
        hash7 = crc16.crc16xmodem(np.uint32(serverIP32 + clientIP32 + salt7)) % modulo
        hash8 = crc16.crc16xmodem(np.uint32(serverIP32 + clientIP32 + salt8)) % modulo
        hash9 = crc16.crc16xmodem(np.uint32(serverIP32 + clientIP32 + salt9)) % modulo
        hash10 = crc16.crc16xmodem(np.uint32(serverIP32 + clientIP32 + salt10)) % modulo
        
        if hash1 in usedHash1 and usedHash1[hash1][1] == key:
            usedHash1[hash1][0] = ts
        elif hash2 in usedHash2 and usedHash2[hash2][1] == key:
            usedHash2[hash2][0] = ts
        elif hash3 in usedHash3 and usedHash3[hash3][1] == key:
            usedHash3[hash3][0] = ts
        elif hash4 in usedHash4 and usedHash4[hash4][1] == key:
            usedHash4[hash4][0] = ts
        elif hash5 in usedHash5 and usedHash5[hash5][1] == key:
            usedHash5[hash5][0] = ts
        elif hash6 in usedHash6 and usedHash6[hash6][1] == key:
            usedHash6[hash6][0] = ts
        elif hash7 in usedHash7 and usedHash7[hash7][1] == key:
            usedHash7[hash7][0] = ts
        elif hash8 in usedHash8 and usedHash8[hash8][1] == key:
            usedHash8[hash8][0] = ts
        elif hash9 in usedHash9 and usedHash9[hash9][1] == key:
            usedHash9[hash9][0] = ts
        elif hash10 in usedHash10 and usedHash10[hash10][1] == key:
            usedHash10[hash10][0] = ts
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


    for j in range(0, 33):
        TABLE_SIZE = 2 ** j
        print('table', j)

        for i in range(1, 11):
            print(i)
            knownlistDict = {}
            netassayTable = {}
            usedHash1 = {}
            usedHash2 = {}
            usedHash3 = {}
            usedHash4 = {}
            usedHash5 = {}
            usedHash6 = {}
            usedHash7 = {}
            usedHash8 = {}
            usedHash9 = {}
            usedHash10 = {}

            for d in known_domains:
                knownlistDict[d] = [0, 0, 0, 0, 0, 0]

            for p in pcap_obj:
                ts = p[0]
                dns_code = p[1]
                ip = p[2]

                # For each packet parse the dns responses
                if (dns_code == -1):
                    try:
                        parse_dns_response(ip, ts, i)
                    except Exception as e:
                        
                        continue
                else:
                    parse_tcp(dns_code, ip, ts, i)

            for i in knownlistDict.keys():
                num_packets = knownlistDict[i][1]
                num_bytes = knownlistDict[i][2]
                num_missed = knownlistDict[i][3]
                num_dns = knownlistDict[i][0]
                if (num_dns > 0 and num_missed < num_dns):
                    knownlistDict[i][4] = num_packets / (1 - (num_missed / num_dns))
                    knownlistDict[i][5] = num_bytes / (1 - (num_missed / num_dns))


            total_dns = 0
            total_packets = 0
            total_bytes = 0
            for i in knownlistDict.items():
                total_dns += i[1][0]
                total_packets += i[1][1]
                total_bytes += i[1][2]
            outfile.write(str(total_dns)+','+str(total_packets)+','+str(total_bytes)+'\n')
        outfile.write('*')

    outfile.close()




            


