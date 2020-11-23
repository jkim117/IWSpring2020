from sys import argv
from sys import exit
import dpkt
import pickle
import glob
import os
import datetime


def check_dup(store_dict, value):
    for d in store_dict:
        indict_ts = store_dict[d][1]
        given_ts = value[1]
        # If same and timestamp is within 0.5 second
        if (store_dict[d][0] == value[0]) and (abs(indict_ts - given_ts) < 0.5):
            return True
    return False

# parse the command line argument and open the file specified
if __name__ == '__main__':
    if len(argv) != 3:
        print('usage: python netassay_python3.py pcap_directory outfileName')
        exit(-1)

    outFile = open(argv[2], 'wb')

    ethPacketList = []

    # Add slash if not there 
    input_dir = argv[1]
    if not argv[1].endswith("/"):
        input_dir = input_dir + "/"

    # List files by ascending modification time
    files = glob.glob(input_dir + "*.pcap*")
    files.sort(key=os.path.getmtime)

    # data structure for dedup
    dedup_dict = {}
    index = 0
    
    
    # Go through files
    for thisf in files:
        with open(thisf, 'rb') as f:
            try:
                pcap_obj = dpkt.pcap.Reader(f)
                #pcap_obj = dpkt.pcapng.Reader(f)
            except:
                pcap_obj = dpkt.pcap.Reader(f)

            for ts, buf in pcap_obj:
                eth = dpkt.ethernet.Ethernet(buf)
                if (eth.type != 2048):
                    continue
                ip = eth.data
                protocol = ip.p
                packet_len = eth.__len__()

                packet_processed = False
                try:
                    if (protocol == 17 and ip.data.sport == 53):

                        ip_header_selected = {
                            '_v_hl':ip._v_hl,
                            'tos':ip.tos,
                            'len':ip.len,
                            'id':ip.id,
                            'p':ip.p,
                            'src':ip.src,
                            'dst':ip.dst,
                            'src_port': ip.data.sport,
                            'dst_port': ip.data.dport
                        }

                        # check dup. If yes, skip
                        if check_dup(dedup_dict, (ip_header_selected,ts)):
                            pass

                        # If DNS, we want the entire IP packet
                        ethPacketList.append([ts, -1, ip]) # 0 is to indicate DNS response
                        packet_processed = True
                        dedup_dict[index%4] = (ip_header_selected,ts)
                        index += 1

                except:
                    pass
                
                try:
                    if (packet_processed == False):
                        # Else, we just want the IP header
                        ip_header = {
                            '_v_hl':ip._v_hl,
                            'tos':ip.tos,
                            'len':ip.len,
                            'id':ip.id,
                            'off':ip.off,
                            'ttl':ip.ttl,
                            'p':ip.p,
                            'sum':ip.sum,
                            'src':ip.src,
                            'dst':ip.dst,
                            'src_port': ip.data.sport,
                            'dst_port': ip.data.dport
                        }
                        ethPacketList.append([ts, packet_len, ip_header])
                except Exception as e:
                    pass
        
    pickle.dump(ethPacketList, outFile)
    outFile.close()
