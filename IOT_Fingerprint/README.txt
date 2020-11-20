1. Run python3 netassay_python_preprocess.py [pcap_file_name] [output_pickle_file_name]
2. Note that you will need the dpkt python library in order to run netassay_python_preprocess.py
3. Note that netassay_python3_preprocess will take a long time to run (2 hours for 15 minute pcap)
3. Run python3 iot_python.py [pickleFile] iot_known_domains.txt allowed_dns_dst.txt banned_dns_dst.txt rules_list
4. This program will print out detections as it finds them. Note that the current detection threshold is set to 25% of the total domains associated with an iot device.
(See page 8 of https://arxiv.org/pdf/2009.01880.pdf). You can modify the detection threshold by changing line 24 of iot_python.py