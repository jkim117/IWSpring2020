from sys import argv
import dpkt
import csv
import socket
import ipaddress
import pickle
import zlib
import numpy as np
import statistics

# Data structure and global variables
allowed_ips = []
banned_ips = []

known_domains = []

unlimitedNetTable = {}
unlimitedKnownDict = {}

netassayTables_timeout = {}
knownlistDicts_timeout = {}

netassayTables_stages = {}
knownlistDicts_stages = {}

usedHashes = {}
STAGES = 2
MEM = 16

TOTAL_PACKETS = 0
TOTAL_DNS = 0

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


    try:
        dns = dpkt.dns.DNS(ip_packet.data.data)
    except:
        return
    answers = dns.an

    if len(answers) <= 0:
        return
    domain = answers[0].name
    domain_name = domain.split('.')

    for t in range(0, 310, 10):
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
                    entry = unlimitedKnownDict[d]
                    unlimitedKnownDict[d][0] = unlimitedKnownDict[d][0] + 1
                    
                    serverIP = socket.inet_ntoa(rr.rdata)

                    key = clientIP + serverIP

                    unlimitedNetTable[key] = d
                    break
            break

    for u in range(0, 550, 50):

        modulo = int((2 ** MEM) / STAGES)

        for d in known_domains:
            if (matchDomain(d, domain)):

                for rr in answers:
                    if (rr.type != 1):
                        continue
                    if (rr.type == 1): #DNS.A
                        entry = knownlistDicts_stages[u][d]
                        knownlistDicts_stages[u][d][0] = knownlistDicts_stages[u][d][0] + 1
                        
                        serverIP = socket.inet_ntoa(rr.rdata)
                        serverIP32 = np.uint64(int.from_bytes(socket.inet_aton(serverIP), byteorder='big'))
                        clientIP32 = np.uint64(int.from_bytes(socket.inet_aton(clientIP), byteorder='big'))
                        #serverIP32 = int.from_bytes(socket.inet_aton(serverIP), byteorder='big')
                        #clientIP32 = int.from_bytes(socket.inet_aton(clientIP), byteorder='big')

                        salts = [np.uint64(134140211), np.uint64(187182238), np.uint64(187238), np.uint64(1853238), np.uint64(1828), np.uint64(12238), np.uint64(72134), np.uint64(152428), np.uint64(164314534), np.uint64(223823)]
                        key = clientIP + serverIP

                        for z in range(0, 8):

                            if modulo > 0:
                                hashz = (zlib.crc32(np.uint64(serverIP32 + clientIP32 + salts[z]))& 0xffffffff) % modulo
                                #hashz = hash_function(serverIP32, clientIP32, salts[z]) % modulo
                            else:
                                hashz = 0

                            if(not hashz in usedHashes[u][z]):
                                usedHashes[u][z][hashz] = [ts, key, domain]
                            elif (ts - usedHashes[u][z][hashz][0] > u): # timestamp expires
                                netassayTables_stages[u][z].pop(usedHashes[u][z][hashz][1])
                                usedHashes[u][z][hashz] = [ts, key, domain]
                            elif(usedHashes[u][z][hashz][1] == key): # update timestamp for existing entry
                                usedHashes[u][z][hashz] = [ts, key, domain]
                            elif(STAGES < z + 2):
                                knownlistDicts_stages[u][d][3] = knownlistDicts_stages[u][d][3]+1
                                break
                            else:
                                continue

                            netassayTables_stages[u][z][key] = d
                            break
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

    serverIP32 = np.uint64(int.from_bytes(socket.inet_aton(source), byteorder='big'))
    clientIP32 = np.uint64(int.from_bytes(socket.inet_aton(dest), byteorder='big'))

    for t in range(0, 310, 10):
        if key in netassayTables_timeout[t]:
            if netassayTables_timeout[t][key][1] + t >= ts:
                netassayTables_timeout[t][key][1] = ts
                d = netassayTables_timeout[t][key][0]
                knownlistDicts_timeout[t][d][1] = knownlistDicts_timeout[t][d][1] + 1
                knownlistDicts_timeout[t][d][2] = knownlistDicts_timeout[t][d][2] + packet_len

    salts = [np.uint64(134140211), np.uint64(187182238), np.uint64(187238), np.uint64(1853238), np.uint64(1828), np.uint64(12238), np.uint64(72134), np.uint64(152428), np.uint64(164314534), np.uint64(223823)]

    for u in range(0, 550, 50):
            
        modulo = int((2 ** MEM) / STAGES)

        for z in range(0, 8):
            if (z + 1 > STAGES):
                break
            if key in netassayTables_stages[u][z]:
                d = netassayTables_stages[u][z][key]

                knownlistDicts_stages[u][d][1] = knownlistDicts_stages[u][d][1] + 1
                knownlistDicts_stages[u][d][2] = knownlistDicts_stages[u][d][2] + packet_len
                
                if modulo > 0:
                    hashz = (zlib.crc32(np.uint64(serverIP32 + clientIP32 + salts[z]))& 0xffffffff) % modulo
                    #hashz = hash_function(serverIP32, clientIP32, salts[z]) % modulo
                else:
                    hashz = 0

                if hashz in usedHashes[u][z] and usedHashes[u][z][hashz][1] == key:
                    usedHashes[u][z][hashz][0] = ts
                else:
                    print("error in hash storage")
                    exit(-1)           
                break 



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
        print('usage: python netassay_python3_p4sim.py knownlist.txt allowed_dns_dst.txt banned_dns_dst.txt')
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

    # Create knownlist
    knownlist = open(argv[1], 'r')
    known_domains = knownlist.read().split()
    knownlist.close()

    for d in known_domains:
            unlimitedKnownDict[d] = [0, 0, 0, 0, 0, 0]

    for t in range(0, 310, 10):
        knownlistDict_t = {}
        for d in known_domains:
            knownlistDict_t[d] = [0, 0, 0, 0, 0, 0]
        knownlistDicts_timeout[t] = knownlistDict_t
        netassayTables_timeout[t] = {}

    for i in range(0, 550, 50):
        knownlistDict_mem = {}
        usedHash_individual_run = []
        netTable_individual = []

        for d in known_domains:
            knownlistDict_mem[d] = [0, 0, 0, 0, 0, 0]

        for l in range(0, 8):
            usedHash_individual_run.append({})
            netTable_individual.append({})

        knownlistDicts_stages[i] = knownlistDict_mem
        netassayTables_stages[i] = usedHash_individual_run
        usedHashes[i] = netTable_individual


    for pcap_count in range(0, 155):
        print('PCAP_COUNT', pcap_count)

        if pcap_count < 69:
            f = open('/u/jjk7/mnt/08_19_2020_T08-11_processed/pcap'+str(pcap_count), 'rb')
        else:
            f = open('/u/jjk7/mnt/anonflow/netassay_output/pcap'+str(pcap_count), 'rb')
        pcap_obj = pickle.load(f)
        f.close()

        num_packets = len(pcap_obj)
        packet_count = 0.0

        for p in pcap_obj:
            TOTAL_PACKETS += 1
            ts = p[0]
            dns_code = p[1]
            ip = p[2]

            # For each packet parse the dns responses
            if (dns_code == -1):
                TOTAL_DNS += 1
                #try:
                try:
                    parse_dns_response(ip, ts)
                except Exception as e:
                    print(e)
                    continue
            else:
                try:
                    parse_tcp(dns_code, ip, ts)
                except Exception as e:
                    print(e)
                    continue

            packet_count += 1
            #if (packet_count % 100000 == 0):
             #   print(packet_count / num_packets)
        

    print('TOTAL PACKETS', TOTAL_PACKETS)
    print('TOTAL DNS', TOTAL_DNS)
    try:
        np.save('knownlistDicts_timeout.npy', knownlistDicts_timeout)
    except Exception as e:
        print(e)

    outfile_t = open('timeout_limits.txt', 'w')

    for t in range(0, 310, 10):
        
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


    outfile_stage = open('timeout_limits_withmem.txt', 'w')
    for v in range(0, 550, 50):

        packet_errors = []
        byte_errors = []

        with open('timeout_limit2_' + str(v) + '.csv', 'w') as csvfile:
            w = csv.writer(csvfile)
            w.writerow(["Domain", "Number of DNS requests", "Missed DNS requests missed", "Number of Packets", "Number of Bytes", "Estimated Packets", "Estimated Bytes", "Error_Packets", "Error_Bytes"])

            for k in knownlistDicts_stages[v].keys():
                num_packets = knownlistDicts_stages[v][k][1]
                num_bytes = knownlistDicts_stages[v][k][2]
                num_missed = knownlistDicts_stages[v][k][3]
                num_dns = knownlistDicts_stages[v][k][0]
                error_packet = -1
                error_byte = -1
                if (num_dns > 0 and num_missed < num_dns):
                    knownlistDicts_stages[v][k][4] = num_packets / (1 - (num_missed / num_dns))
                    knownlistDicts_stages[v][k][5] = num_bytes / (1 - (num_missed / num_dns))

                    if (unlimitedKnownDict[k][1] > 0):
                        error_packet = abs(unlimitedKnownDict[k][1] - knownlistDicts_stages[v][k][4]) / unlimitedKnownDict[k][1]
                        packet_errors.append(error_packet)
                    if (unlimitedKnownDict[k][2] > 0):
                        error_byte = abs(unlimitedKnownDict[k][2] - knownlistDicts_stages[v][k][5]) / unlimitedKnownDict[k][2]
                        byte_errors.append(error_byte)
                w.writerow([k, num_dns, num_missed, num_packets, num_bytes, knownlistDicts_stages[v][k][4], knownlistDicts_stages[v][k][5], error_packet, error_byte])

        packet_error_med = statistics.median(packet_errors)
        byte_error_med = statistics.median(byte_errors)
        total_dns = 0
        total_packets = 0
        total_bytes = 0
        total_dns_missed = 0
        total_est_packets = 0
        total_est_bytes = 0
        for l in knownlistDicts_stages[v].items():
            total_dns += l[1][0]
            total_packets += l[1][1]
            total_bytes += l[1][2]
            total_dns_missed += l[1][3]
            total_est_packets += l[1][4]
            total_est_bytes += l[1][5]
        outfile_stage.write(str(total_dns)+','+str(total_packets)+','+str(total_bytes)+','+str(total_dns_missed)+','+str(total_est_packets)+','+str(total_est_bytes)+','+str(packet_error_med)+','+str(byte_error_med)+'\n')
    outfile_stage.close()





            


