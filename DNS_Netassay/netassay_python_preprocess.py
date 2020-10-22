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
            ethPacketList.append([ts, eth])
        
    pickle.dump(ethPacketList, outFile)
    outFile.close()