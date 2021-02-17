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

unlimitedNetTable = {}
unlimitedKnownDict = {}

netassayTables_parser = [] # Key is concatentation of server IP/client IP. Value is a knownlist domain name
knownlistDicts_parser = [] # Key is knowlist domain, values are number of dns, number of packets, number of bytes, number missed dns, estimated packets, estimated bytes

netassayTables_timeout = {}
knownlistDicts_timeout = {}

netassayTables_stages = {}
knownlistDicts_stages = {}

usedHashes = {}

TIMEOUT = 300 # standard timeout

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

    if len(answers <= 0):
        return
    domain = answers[0].name
    domain_name = domain.split('.')

    for d in known_domains:
        if (matchDomain(d, domain)):
            
            for rr in answers:
                if (rr.type != 1):
                    continue
                if (rr.type == 1): #DNS.A
                    entry = unlimitedKnownDict[d]
                    unlimitedKnownDict[d][0] = unlimitedKnownDict[d][0] + 1
                    
                    serverIP = socket.inet_ntoa(rr.rdata)

                    key = clientIP + serverIP

                    unlimitedNetTable[key] = d
                    break
            break

    for g in [1, 2, 4, 8]:
        for q in range(0, 33):
            # Parser limitations
            parser_test = True
            if (len(domain_name) > 4):
                parser_test = False
                continue
            for part in domain_name:
                if (len(part) > 15):
                    parser_test = False
                    break
            if (parser_test == False):
                continue

            modulo = int((2 ** q) / g)

            for d in known_domains:
                if (matchDomain(d, domain)):

                    for rr in answers:
                        if (rr.type != 1):
                            continue
                        if (rr.type == 1): #DNS.A
                            entry = knownlistDicts_stages[g][q][d]
                            knownlistDicts_stages[g][q][d][0] = knownlistDicts_stages[g][q][d][0] + 1
                            
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

                            if(not hash1 in usedHashes[g][q][0]):
                                usedHashes[g][q][0][hash1] = [ts, key, domain]
                            elif (ts - usedHashes[g][q][0][hash1][0] > TIMEOUT): # timestamp expires
                                netassayTables_stages[g][q].pop(usedHashes[g][q][0][hash1][1])
                                usedHashes[g][q][0][hash1] = [ts, key, domain]
                            elif(usedHashes[g][q][0][hash1][1] == key): # update timestamp for existing entry
                                usedHashes[g][q][0][hash1] = [ts, key, domain]
                            elif(g < 2):
                                knownlistDicts_stages[g][q][d][3] = knownlistDicts_stages[g][q][d][3]+1
                                break

                            elif(not hash2 in usedHashes[g][q][1]):
                                usedHashes[g][q][1][hash2] = [ts, key, domain]
                            elif (ts - usedHashes[g][q][1][hash2][0] > TIMEOUT): # timestamp expires
                                netassayTables_stages[g][q].pop(usedHashes[g][q][1][hash2][1])
                                usedHashes[g][q][1][hash2] = [ts, key, domain]
                            elif(usedHashes[g][q][1][hash2][1] == key): # update timestamp for existing entry
                                usedHashes[g][q][1][hash2] = [ts, key, domain]
                            elif(g < 3):
                                knownlistDicts_stages[g][q][d][3] = knownlistDicts_stages[g][q][d][3]+1
                                break
                            
                            elif(not hash3 in usedHashes[g][q][2]):
                                usedHashes[g][q][2][hash3] = [ts, key, domain]
                            elif (ts - usedHashes[g][q][2][hash3][0] > TIMEOUT): # timestamp expires
                                netassayTables_stages[g][q].pop(usedHashes[g][q][2][hash3][1])
                                usedHashes[g][q][2][hash3] = [ts, key, domain]
                            elif(usedHashes[g][q][2][hash3][1] == key): # update timestamp for existing entry
                                usedHashes[g][q][2][hash3] = [ts, key, domain]
                            elif(g < 4):
                                knownlistDicts_stages[g][q][d][3] = knownlistDicts_stages[g][q][d][3]+1
                                break

                            elif(not hash4 in usedHashes[g][q][3]):
                                usedHashes[g][q][3][hash4] = [ts, key, domain]
                            elif (ts - usedHashes[g][q][3][hash4][0] > TIMEOUT): # timestamp expires
                                netassayTables_stages[g][q].pop(usedHashes[g][q][3][hash4][1])
                                usedHashes[g][q][3][hash4] = [ts, key, domain]
                            elif(usedHashes[g][q][3][hash4][1] == key): # update timestamp for existing entry
                                usedHashes[g][q][3][hash4] = [ts, key, domain]
                            elif(g < 5):
                                knownlistDicts_stages[g][q][d][3] = knownlistDicts_stages[g][q][d][3]+1
                                break

                            elif(not hash5 in usedHashes[g][q][4]):
                                usedHashes[g][q][4][hash5] = [ts, key, domain]
                            elif (ts - usedHashes[g][q][4][hash5][0] > TIMEOUT): # timestamp expires
                                netassayTables_stages[g][q].pop(usedHashes[g][q][4][hash5][1])
                                usedHashes[g][q][4][hash5] = [ts, key, domain]
                            elif(usedHashes[g][q][4][hash5][1] == key): # update timestamp for existing entry
                                usedHashes[g][q][4][hash5] = [ts, key, domain]
                            elif(g < 6):
                                knownlistDicts_stages[g][q][d][3] = knownlistDicts_stages[g][q][d][3]+1
                                break

                            elif(not hash6 in usedHashes[g][q][5]):
                                usedHashes[g][q][5][hash6] = [ts, key, domain]
                            elif (ts - usedHashes[g][q][5][hash6][0] > TIMEOUT): # timestamp expires
                                netassayTables_stages[g][q].pop(usedHashes[g][q][5][hash6][1])
                                usedHashes[g][q][5][hash6] = [ts, key, domain]
                            elif(usedHashes[g][q][5][hash6][1] == key): # update timestamp for existing entry
                                usedHashes[g][q][5][hash6] = [ts, key, domain]
                            elif(g < 7):
                                knownlistDicts_stages[g][q][d][3] = knownlistDicts_stages[g][q][d][3]+1
                                break

                            elif(not hash7 in usedHashes[g][q][6]):
                                usedHashes[g][q][6][hash7] = [ts, key, domain]
                            elif (ts - usedHashes[g][q][6][hash7][0] > TIMEOUT): # timestamp expires
                                netassayTables_stages[g][q].pop(usedHashes[g][q][6][hash7][1])
                                usedHashes[g][q][6][hash7] = [ts, key, domain]
                            elif(usedHashes[g][q][6][hash7][1] == key): # update timestamp for existing entry
                                usedHashes[g][q][6][hash7] = [ts, key, domain]
                            elif(g < 8):
                                knownlistDicts_stages[g][q][d][3] = knownlistDicts_stages[g][q][d][3]+1
                                break

                            elif(not hash8 in usedHashes[g][q][7]):
                                usedHashes[g][q][7][hash8] = [ts, key, domain]
                            elif (ts - usedHashes[g][q][7][hash8][0] > TIMEOUT): # timestamp expires
                                netassayTables_stages[g][q].pop(usedHashes[g][q][7][hash8][1])
                                usedHashes[g][q][7][hash8] = [ts, key, domain]
                            elif(usedHashes[g][q][7][hash8][1] == key): # update timestamp for existing entry
                                usedHashes[g][q][7][hash8] = [ts, key, domain]
                            elif(g < 9):
                                knownlistDicts_stages[g][q][d][3] = knownlistDicts_stages[g][q][d][3]+1
                                break

                            elif(not hash9 in usedHashes[g][q][8]):
                                usedHashes[g][q][8][hash9] = [ts, key, domain]
                            elif (ts - usedHashes[g][q][8][hash9][0] > TIMEOUT): # timestamp expires
                                netassayTables_stages[g][q].pop(usedHashes[g][q][8][hash9][1])
                                usedHashes[g][q][8][hash9] = [ts, key, domain]
                            elif(usedHashes[g][q][8][hash9][1] == key): # update timestamp for existing entry
                                usedHashes[g][q][8][hash9] = [ts, key, domain]
                            elif(g < 10):
                                knownlistDicts_stages[g][q][d][3] = knownlistDicts_stages[g][q][d][3]+1
                                break

                            elif(not hash10 in usedHashes[g][q][9]):
                                usedHashes[g][q][9][hash10] = [ts, key, domain]
                            elif (ts - usedHashes[g][q][9][hash10][0] > TIMEOUT): # timestamp expires
                                netassayTables_stages[g][q].pop(usedHashes[g][q][9][hash10][1])
                                usedHashes[g][q][9][hash10] = [ts, key, domain]
                            elif(usedHashes[g][q][9][hash10][1] == key): # update timestamp for existing entry
                                usedHashes[g][q][9][hash10] = [ts, key, domain]
                            else:
                                knownlistDicts_stages[g][q][d][3] = knownlistDicts_stages[g][q][d][3]+1
                                break

                            netassayTables_stages[g][q][key] = d
                            break
                    break

    for t in range(0, 61, 3):
        # Parser limitations
        parser_test = True
        if (len(domain_name) > 4):
            parser_test = False
            continue
        for part in domain_name:
            if (len(part) > 15):
                parser_test = False
                break
        if (parser_test == False):
            continue
        
        for d in known_domains:
            if (matchDomain(d, domain)):
                

                for rr in answers:
                    if (rr.type != 1):
                        continue
                    if (rr.type == 1): #DNS.A
                        entry = knownlistDicts_timeout[t][d]
                        knownlistDicts_timeout[t][d][0] = knownlistDicts_timeout[t][d][0] + 1
                        
                        serverIP = socket.inet_ntoa(rr.rdata)

                        key = clientIP + serverIP

                        netassayTables_timeout[t][key] = [d, ts]
                        break
                break

    for i in range(0, 31):
    # Parser limitations

        parser_test = True
        if (len(domain_name) > 4):
            parser_test = False
            continue
        for part in domain_name:
            if (len(part) > i):
                parser_test = False
                break
        if (parser_test == False):
            continue

        for d in known_domains:
            if (matchDomain(d, domain)):
                

                for rr in answers:
                    if (rr.type != 1):
                        continue
                    if (rr.type == 1): #DNS.A
                        entry = knownlistDicts_parser[i][d]
                        knownlistDicts_parser[i][d][0] = knownlistDicts_parser[i][d][0] + 1
                        
                        serverIP = socket.inet_ntoa(rr.rdata)

                        key = clientIP + serverIP

                        netassayTables_parser[i][key] = d
                        break
                break
        

def parse_tcp(packet_len, ip_packet, ts):
    source = socket.inet_ntoa(ip_packet['src']) #server
    dest = socket.inet_ntoa(ip_packet['dst']) #client
    
    key = dest + source

    if key in unlimitedNetTable:
            d = unlimitedNetTable[key]
            unlimitedKnownDict[d][1] = unlimitedKnownDict[d][1] + 1
            unlimitedKnownDict[d][2] = unlimitedKnownDict[d][2] + packet_len

    for g in [1, 2, 4, 8]:
        for q in range(0, 33):
            
            modulo = int((2 ** q) / g)
            if key in netassayTables_stages[g][q]:
                d = netassayTables_stages[g][q][key]
                knownlistDicts_stages[g][q][d][1] = knownlistDicts_stages[g][q][d][1] + 1
                knownlistDicts_stages[g][q][d][2] = knownlistDicts_stages[g][q][d][2] + packet_len

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
                
                if hash1 in usedHashes[g][q][0] and usedHashes[g][q][0][hash1][1] == key:
                    usedHashes[g][q][0][hash1][0] = ts
                elif hash2 in usedHashes[g][q][1] and usedHashes[g][q][1][hash2][1] == key:
                    usedHashes[g][q][1][hash2][0] = ts
                elif hash3 in usedHashes[g][q][2] and usedHashes[g][q][2][hash3][1] == key:
                    usedHashes[g][q][2][hash3][0] = ts
                elif hash4 in usedHashes[g][q][3] and usedHashes[g][q][3][hash4][1] == key:
                    usedHashes[g][q][3][hash4][0] = ts
                elif hash5 in usedHashes[g][q][4] and usedHashes[g][q][4][hash5][1] == key:
                    usedHashes[g][q][4][hash5][0] = ts
                elif hash6 in usedHashes[g][q][5] and usedHashes[g][q][5][hash6][1] == key:
                    usedHashes[g][q][5][hash6][0] = ts
                elif hash7 in usedHashes[g][q][6] and usedHashes[g][q][6][hash7][1] == key:
                    usedHashes[g][q][6][hash7][0] = ts
                elif hash8 in usedHashes[g][q][7] and usedHashes[g][q][7][hash8][1] == key:
                    usedHashes[g][q][7][hash8][0] = ts
                elif hash9 in usedHashes[g][q][8] and usedHashes[g][q][8][hash9][1] == key:
                    usedHashes[g][q][8][hash9][0] = ts
                elif hash10 in usedHashes[g][q][9] and usedHashes[g][q][9][hash10][1] == key:
                    usedHashes[g][q][9][hash10][0] = ts
                else:
                    print("error in hash storage")
                    exit(-1)            

    for t in range(0, 610, 30):
        if key in netassayTables_timeout[t]:
            if netassayTables_timeout[t][key][1] + t >= ts:
                netassayTables_timeout[t][key][1] = ts
                d = netassayTables_timeout[t][key][0]
                knownlistDicts_timeout[t][d][1] = knownlistDicts_timeout[t][d][1] + 1
                knownlistDicts_timeout[t][d][2] = knownlistDicts_timeout[t][d][2] + packet_len


    for i in range(0, 31):
        if key in netassayTables_parser[i]:
            d = netassayTables_parser[i][key]
            knownlistDicts_parser[i][d][1] = knownlistDicts_parser[i][d][1] + 1
            knownlistDicts_parser[i][d][2] = knownlistDicts_parser[i][d][2] + packet_len
        


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
        print('usage: python netassay_python3_p4sim.py pickleFile knownlist.txt allowed_dns_dst.txt banned_dns_dst.txt')
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

    for d in known_domains:
            unlimitedKnownDict[d] = [0, 0, 0, 0, 0, 0]

    for i in range(0, 31):
        knownlistDict_i = {}
        for d in known_domains:
            knownlistDict_i[d] = [0, 0, 0, 0, 0, 0]
        knownlistDicts_parser.append(knownlistDict_i)
        netassayTables_parser.append({})

    for t in range(0, 610, 30):
        knownlistDict_t = {}
        for d in known_domains:
            knownlistDict_t[d] = [0, 0, 0, 0, 0, 0]
        knownlistDicts_timeout[t] = knownlistDict_t
        netassayTables_timeout[t] = {}

    for i in [1, 2, 4, 8]:
        knownlistDict_mem = []
        netassayTable_mem = []
        usedHash_mem = []
        for q in range(0, 33):
            knownlistDict_q = {}

            for d in known_domains:
                knownlistDict_q[d] = [0, 0, 0, 0, 0, 0]

            usedHash_individual_run = []
            for l in range(0, 10):
                usedHash_individual_run.append({})
            
            knownlistDict_mem.append(knownlistDict_q)
            netassayTable_mem.append({})
            usedHash_mem.append(usedHash_individual_run)
        
        knownlistDicts_stages[i] = knownlistDict_mem
        netassayTables_stages[i] = netassayTable_mem
        usedHashes[i] = usedHash_mem

    f = open(argv[1], 'rb')
    pcap_obj = pickle.load(f)
    f.close()

    for p in pcap_obj:
        ts = p[0]
        dns_code = p[1]
        ip = p[2]

        # For each packet parse the dns responses
        if (dns_code == -1):
            #try:
            parse_dns_response(ip, ts)
            '''except Exception as e:
                print(e)
                continue'''
        else:
            parse_tcp(dns_code, ip, ts)


    outfile_stage = open('stage_limits.txt', 'w')
    for v in [1, 2, 4, 8]:
        for c in range(0, 33):

            packet_errors = []
            byte_errors = []

            with open('stage_limit' + str(v) + '_' + str(c) + '.csv', 'w') as csvfile:
                w = csv.writer(csvfile)
                w.writerow(["Domain", "Number of DNS requests", "Missed DNS requests missed", "Number of Packets", "Number of Bytes", "Estimated Packets", "Estimated Bytes", "Error_Packets", "Error_Bytes"])

                for k in knownlistDicts_stages[v][c].keys():
                    num_packets = knownlistDicts_stages[v][c][k][1]
                    num_bytes = knownlistDicts_stages[v][c][k][2]
                    num_missed = knownlistDicts_stages[v][c][k][3]
                    num_dns = knownlistDicts_stages[v][c][k][0]
                    error_packet = -1
                    error_byte = -1
                    if (num_dns > 0 and num_missed < num_dns):
                        knownlistDicts_stages[v][c][k][4] = num_packets / (1 - (num_missed / num_dns))
                        knownlistDicts_stages[v][c][k][5] = num_bytes / (1 - (num_missed / num_dns))

                        if (knownlistDicts_parser[15][k][1] > 0):
                            error_packet = abs(knownlistDicts_parser[15][k][1] - knownlistDicts_stages[v][c][k][4]) / knownlistDicts_parser[15][k][1]
                            packet_errors.append(error_packet)
                        if (knownlistDicts_parser[15][k][2] > 0):
                            error_byte = abs(knownlistDicts_parser[15][k][2] - knownlistDicts_stages[v][c][k][5]) / knownlistDicts_parser[15][k][2]
                            byte_errors.append(error_byte)
                    w.writerow([k, num_dns, num_missed, num_packets, num_bytes, knownlistDicts_stages[v][c][k][4], knownlistDicts_stages[v][c][k][5], error_packet, error_byte])

            packet_error_med = statistics.median(packet_errors)
            byte_error_med = statistics.median(byte_errors)
            total_dns = 0
            total_packets = 0
            total_bytes = 0
            total_dns_missed = 0
            total_est_packets = 0
            total_est_bytes = 0
            for l in knownlistDicts_stages[v][c].items():
                total_dns += l[1][0]
                total_packets += l[1][1]
                total_bytes += l[1][2]
                total_dns_missed += l[1][3]
                total_est_packets += l[1][4]
                total_est_bytes += l[1][5]
            outfile_stage.write(str(total_dns)+','+str(total_packets)+','+str(total_bytes)+','+str(total_dns_missed)+','+str(total_est_packets)+','+str(total_est_bytes)+','+str(packet_error_med)+','+str(byte_error_med)+'\n')
        outfile_stage.write('*')

    outfile_stage.close()


    outfile_t = open('timeout_limits.txt', 'w')

    for t in range(0, 610, 30):
        
        with open('timeout_limit' + str(t) + '.csv', 'w') as csvfile:
            w = csv.writer(csvfile)
            w.writerow(["Domain", "Number of DNS requests", "Missed DNS requests missed", "Number of Packets", "Number of Bytes", "Estimated Packets", "Estimated Bytes"])

            for j in knownlistDicts_timeout[t].keys():
                num_packets = knownlistDicts_timeout[t][j][1]
                num_bytes = knownlistDicts_timeout[t][j][2]
                num_missed = knownlistDicts_timeout[t][j][3]
                num_dns = knownlistDicts_timeout[t][j][0]
                if (num_dns > 0 and num_missed < num_dns):
                    knownlistDicts_timeout[t][j][4] = num_packets / (1 - (num_missed / num_dns))
                    knownlistDicts_timeout[t][j][5] = num_bytes / (1 - (num_missed / num_dns))
                w.writerow([j, num_dns, num_missed, num_packets, num_bytes, knownlistDicts_timeout[t][j][4], knownlistDicts_timeout[t][j][5]])

        total_dns = 0
        total_packets = 0
        total_bytes = 0
        for m in knownlistDicts_timeout[t].items():
            total_dns += m[1][0]
            total_packets += m[1][1]
            total_bytes += m[1][2]
        outfile_t.write(str(total_dns)+','+str(total_packets)+','+str(total_bytes)+'\n')

    outfile_t.close()

    outfile = open('parse_limits.txt', 'w')

    for i in range(0, 31):
        
        with open('parse_limit' + str(i * 4) + '.csv', 'w') as csvfile:
            w = csv.writer(csvfile)
            w.writerow(["Domain", "Number of DNS requests", "Missed DNS requests missed", "Number of Packets", "Number of Bytes", "Estimated Packets", "Estimated Bytes"])

            for j in knownlistDicts_parser[i].keys():
                num_packets = knownlistDicts_parser[i][j][1]
                num_bytes = knownlistDicts_parser[i][j][2]
                num_missed = knownlistDicts_parser[i][j][3]
                num_dns = knownlistDicts_parser[i][j][0]
                if (num_dns > 0 and num_missed < num_dns):
                    knownlistDicts_parser[i][j][4] = num_packets / (1 - (num_missed / num_dns))
                    knownlistDicts_parser[i][j][5] = num_bytes / (1 - (num_missed / num_dns))
                w.writerow([j, num_dns, num_missed, num_packets, num_bytes, knownlistDicts_parser[i][j][4], knownlistDicts_parser[i][j][5]])

        total_dns = 0
        total_packets = 0
        total_bytes = 0
        for m in knownlistDicts_parser[i].items():
            total_dns += m[1][0]
            total_packets += m[1][1]
            total_bytes += m[1][2]
        outfile.write(str(total_dns)+','+str(total_packets)+','+str(total_bytes)+'\n')

    outfile.close()


    for i in unlimitedKnownDict.keys():
        num_packets = unlimitedKnownDict[i][1]
        num_bytes = unlimitedKnownDict[i][2]
        num_missed = unlimitedKnownDict[i][3]
        num_dns = unlimitedKnownDict[i][0]
        if (num_dns > 0 and num_missed < num_dns):
            unlimitedKnownDict[i][4] = num_packets / (1 - (num_missed / num_dns))
            unlimitedKnownDict[i][5] = num_bytes / (1 - (num_missed / num_dns))


    with open('unlimited_15min.csv', 'w') as csvfile:
        w = csv.writer(csvfile)
        w.writerow(["Domain", "Number of DNS requests", "Missed DNS requests missed", "Number of Packets", "Number of Bytes", "Estimated Packets", "Estimated Bytes"])

        for i in unlimitedKnownDict.items():
            w.writerow([i[0], i[1][0], i[1][3], i[1][1], i[1][2], i[1][4], i[1][5]])

            


