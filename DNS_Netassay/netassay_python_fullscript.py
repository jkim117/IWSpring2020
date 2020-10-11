import os

fileNames = [
'p4netassay_15mins_20200407T1504_ontasanony_dedupped_sliced_00000_20200407150432.pcap',
'p4netassay_15mins_20200407T1504_ontasanony_dedupped_sliced_00001_20200407150517.pcap',
'p4netassay_15mins_20200407T1504_ontasanony_dedupped_sliced_00002_20200407150602.pcap',
'p4netassay_15mins_20200407T1504_ontasanony_dedupped_sliced_00003_20200407150647.pcap',
'p4netassay_15mins_20200407T1504_ontasanony_dedupped_sliced_00004_20200407150732.pcap',
'p4netassay_15mins_20200407T1504_ontasanony_dedupped_sliced_00005_20200407150817.pcap',
'p4netassay_15mins_20200407T1504_ontasanony_dedupped_sliced_00006_20200407150902.pcap',
'p4netassay_15mins_20200407T1504_ontasanony_dedupped_sliced_00007_20200407150947.pcap',
'p4netassay_15mins_20200407T1504_ontasanony_dedupped_sliced_00008_20200407151032.pcap',
'p4netassay_15mins_20200407T1504_ontasanony_dedupped_sliced_00009_20200407151117.pcap',
'p4netassay_15mins_20200407T1504_ontasanony_dedupped_sliced_00010_20200407151202.pcap',
'p4netassay_15mins_20200407T1504_ontasanony_dedupped_sliced_00011_20200407151247.pcap',
'p4netassay_15mins_20200407T1504_ontasanony_dedupped_sliced_00012_20200407151332.pcap',
'p4netassay_15mins_20200407T1504_ontasanony_dedupped_sliced_00013_20200407151417.pcap',
'p4netassay_15mins_20200407T1504_ontasanony_dedupped_sliced_00014_20200407151502.pcap',
'p4netassay_15mins_20200407T1504_ontasanony_dedupped_sliced_00015_20200407151547.pcap',
'p4netassay_15mins_20200407T1504_ontasanony_dedupped_sliced_00016_20200407151632.pcap',
'p4netassay_15mins_20200407T1504_ontasanony_dedupped_sliced_00017_20200407151717.pcap',
'p4netassay_15mins_20200407T1504_ontasanony_dedupped_sliced_00018_20200407151802.pcap',
'p4netassay_15mins_20200407T1504_ontasanony_dedupped_sliced_00019_20200407151847.pcap',
'p4netassay_15mins_20200407T1504_ontasanony_dedupped_sliced_00020_20200407151932.pcap']

filePath = '/n/fs/p4netassay/data/new_trace/sliced/'

outFile = open('output_netassay_python.txt', 'w')

i = 0
for f in fileNames:
    print(f)
    res = os.popen('python3 netassay_python3.py ' + filePath + f + ' wildcard_knownlist.txt allowed_dns_dst.txt banned_dns_dst.txt ' + str(i)).read()
    outFile.write(res + '\n')
    i += 1
outFile.close()
    
