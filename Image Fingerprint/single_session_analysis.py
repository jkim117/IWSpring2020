# Uses length instead of sequence numbers
from sys import argv
import dpkt
import socket
import ipaddress
import matplotlib
import matplotlib.pyplot as plt
import csv
import json

# parse the command line argument and open the file specified
if __name__ == '__main__':

    # dest ip (client), src ip (server), client_port, session ID
    # jjk7_safari_persistent: sessions = [['10.9.95.159', '159.203.178.14', 61481, 0],['10.9.95.159', '159.203.178.14', 61482, 1],['10.9.95.159', '159.203.178.14', 61483, 2],['10.9.95.159', '159.203.178.14', 61485, 3],['10.9.95.159', '159.203.178.14', 61487, 4],['10.9.95.159', '159.203.178.14', 61488, 5],['10.9.95.159', '159.203.178.14', 61489, 6],['10.9.95.159', '159.203.178.14', 61490, 7],['10.9.95.159', '159.203.178.14', 61491, 8],['10.9.95.159', '159.203.178.14', 61492, 9]]
    # jjk7_chrome_persistent: sessions = [['10.9.95.159', '159.203.178.14', 61506, 0],['10.9.95.159', '159.203.178.14', 61507, 1],['10.9.95.159', '159.203.178.14', 61514, 2],['10.9.95.159', '159.203.178.14', 61515, 3],['10.9.95.159', '159.203.178.14', 61516, 4],['10.9.95.159', '159.203.178.14', 61517, 5],['10.9.95.159', '159.203.178.14', 61518, 6]]
    # bbc_safari_persistent:
    #sessions = [['10.9.95.159', '199.232.36.81',61683,0],['10.9.95.159', '199.232.36.81',61679,1],['10.9.95.159', '23.204.254.228',61682,2],['10.9.95.159', '23.204.254.228',61681,3],['10.9.95.159', '184.26.46.222',61739,4],['10.9.95.159', '184.26.46.222',61738,5],['10.9.95.159', '199.232.36.81',61678,6]]
    # bbc_chrome_persistent: 
    sessions = [['10.9.95.159', '151.101.208.81',61774,0],['10.9.95.159', '151.101.208.81',61816,1],['10.9.95.159', '184.26.46.222',61776,2],['10.9.95.159', '184.26.46.222',61777,3],['10.9.95.159', '184.26.46.222',61778,4],['10.9.95.159', '184.26.46.222',61779,5],['10.9.95.159', '184.26.46.222',61780,6],['10.9.95.159', '184.26.46.222',61781,7],['10.9.95.159', '184.26.46.222',61782,8],['10.9.95.159', '184.26.46.222',61783,9],['10.9.95.159', '184.26.46.222',61784,10],['10.9.95.159', '184.26.46.222',61827,11],['10.9.95.159', '129.213.175.138',61789,12],['10.9.95.159', '129.213.175.138',61817,13]]

    # Lincoln:
    #sessions = [['10.9.95.159', '144.208.79.222',57262,0],['10.9.95.159', '144.208.79.222',57263,1],['10.9.95.159', '144.208.79.222',57264,2],['10.9.95.159', '144.208.79.222',57266,3],['10.9.95.159', '144.208.79.222',57267,4],['10.9.95.159', '144.208.79.222',57268,5],['10.9.95.159', '144.208.79.222',57269,6],['10.9.95.159', '144.208.79.222',57270,7],['10.9.95.159', '144.208.79.222',57271,8],['10.9.95.159', '144.208.79.222',57272,9],['10.9.95.159', '172.217.165.131',57265,10]]
    times = [] # index corresponds to session ID, value is list of timestsamps
    seq_nums = [] # index corresponds to session ID, value is a list of seq_nums
    fin_packets = [] # list of [time, seq, sessionID]

    for i in range(0, len(sessions)):
        times.append([])
        seq_nums.append([])


    with open(argv[1], 'rb') as f:
        #pcap_obj = dpkt.pcap.Reader(f)
        pcap_obj = dpkt.pcapng.Reader(f)

        first_ts = 0
        for ts, buf in pcap_obj:
            if first_ts == 0:
                first_ts = ts
            eth = dpkt.ethernet.Ethernet(buf)

            if (eth.type != 2048): # If not IPV4
                continue
            ip = eth.data
            protocol = ip.p

            # Parse packets
            try:
                if (protocol == 6):
                    dest = socket.inet_ntoa(ip.dst)
                    src = socket.inet_ntoa(ip.src)
                    tcp = ip.data
                    seq = tcp.seq
                    flags = tcp.flags
                    client_port = tcp.dport

                    for s in sessions:
                        if dest == s[0] and src == s[1] and client_port == s[2]:
                            times[s[3]].append(ts - first_ts)
                            seq_nums[s[3]].append(seq)

                            if flags & 1 == 1:
                                fin_packets.append([ts-first_ts,seq, s[3]])                            
                            

                    #if dest == '10.9.95.159' and src == '104.117.44.8' and client_port == 54434:
                    #if dest == '10.9.95.159' and src == '159.203.178.14' and client_port == 54606:
                    '''if dest == '10.9.95.159' and src == '159.203.178.14' and client_port == 54937:
                        times.append(ts - first_ts)
                        running_sum = running_sum + ip.len
                        lengths.append(running_sum)

                    if dest == '10.9.95.159' and src == '159.203.178.14' and client_port == 54934:
                        times1.append(ts - first_ts)
                        running_sum = running_sum + ip.len
                        lengths1.append(running_sum)'''
                    
                    
            except Exception as e:
                print(e)
                continue

    for i in range(0, len(sessions)):
        plt.plot(times[i], seq_nums[i], '.')
        for j in range(0, len(fin_packets)):
            if i == fin_packets[j][2]:
                plt.plot([fin_packets[j][0]],[fin_packets[j][1]],'v')
        plt.show()

 
   






