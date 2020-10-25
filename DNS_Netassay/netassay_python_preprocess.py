from sys import argv
import dpkt
import pickle

# parse the command line argument and open the file specified
if __name__ == '__main__':
    if len(argv) != 3:
        print('usage: python netassay_python3.py capture.pcap outfileName')
        exit(-1)

    outFile = open(argv[2], 'wb')

    ethPacketList = []
    with open(argv[1], 'rb') as f:
        try:
            pcap_obj = dpkt.pcapng.Reader(f)
        except:
            pcap_obj = dpkt.pcap.Reader(f)

        for ts, buf in pcap_obj:
            eth = dpkt.ethernet.Ethernet(buf)
            if (eth.type != 2048):
                continue
            ip = eth.data
            protocol = ip.p
            packet_len = eth.len

            packet_processed = False
            try:
                if (protocol == 17 and ip.data.sport == 53):
                    # If DNS, we want the entire IP packet
                    ethPacketList.append([ts, -1, ip]) # 0 is to indicate DNS response
                    packet_processed = True
            except:
                pass

            if (packet_processed == False):
                # Else, we just want the IP header
                ethPacketList.append([ts, packet_len, ip.__hdr__])
        
    pickle.dump(ethPacketList, outFile)
    outFile.close()