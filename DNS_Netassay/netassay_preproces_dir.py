from sys import argv
import dpkt
import pickle
import os

# parse the command line argument and open the file specified
if __name__ == '__main__':
    if len(argv) != 3:
        print('usage: python netassay_python3.py dir out_dir')
        exit(-1)

    in_dir = argv[1]
    # pre-check before running
    for file in os.listdir(in_dir):
        print(in_dir + file)

    count = 0
    for file in os.listdir(in_dir):
        in_file = in_dir + file
        print(in_file)
        
        outFile = open(argv[2] + 'pcap' + str(count), 'wb')
        count += 1

        count_dns_fail = 0
        count_other_fail = 0

        ethPacketList = []
        with open(in_file, 'rb') as f:
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
                        # If DNS, we want the entire IP packet
                        ethPacketList.append([ts, -1, ip]) # 0 is to indicate DNS response
                        packet_processed = True
                except Exception as e:
                    print(e)
                    count_dns_fail += 1
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
                    count_other_fail += 1
                    pass
            
        pickle.dump(ethPacketList, outFile)
        outFile.close()
        print('dns_fail', count_dns_fail)
        print('other_fail', count_other_fail)