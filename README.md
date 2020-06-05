# IWSpring2020

netassay_bmv2_60.p4 -> uses a single match action table and thus is limited to parsing domain names of up to four labels of up to 15 characters each. Thus, a max width of 60 characters is allowed for a domain

netassay_bmv2_155.p4 -> uses multiple match action tables and thus can parse up to five labels of 31 characters each. Thus a max width of 155 characters is allowed for a domain.

known_domains.txt -> File used to contain list of known domains

knownlist_json_60.py -> uses known_domains.txt to create a JSON file to populate the match action table for netassay_bmv2_60.p4

knownlist_json_155.py -> uses known_domains.txt to create a JSON file to populate the match action tables for netassay_bmv2_155.p4

netassay_python3.py -> outputs useful stats on a pcap file and also outputs netassay results without restrictions of P4

netassay_python3_p4sim60.py -> outputs netassay results simulating the restrictions of netassay_bmv2_60. Most accurate replication of how the P4 program behaves

netassay_python3_p4sim155.py -> outputs netassay results simulating the restrictions of netassay_bmv2_155. Most accurate replication of how the P4 program behaves

################### INSTRUCTIONS TO TEST RUN netassay_bmv2_60.p4 ###################

All tests were run through the P4 Tutorial Virtual Machine using VirtualBox.

First, download the repo from GitHub: https://github.com/jkim117/IWSpring2020

Run "python IWSpring2020/knownlist_json_60.py". This will take domains from the txt file "known_domains.txt" and convert it into a JSON file to be used to populate the match action table.

Copy IWSpring2020/netassay_bmv2_60.p4 and IWSpring2020/s1-runtime.json into the directory IWSpring2020/tutorial/exercises/calc2

cd into IWSpring2020/tutorial/exercises/calc2 and rename netassay_bmv2_60.p4 to calc2.p4

Next, type: "make run"

Once Mininet is running, type "xterm h1"

In the new terminal, cd back to the IWSpring2020 main directory and execute:

"tcpreplay -i eth0 smallFlows.pcap"

Now, in the main terminal running Mininet, type "xterm s1"

In that new terminal type "simple_switch_CLI"

Then type: "register_read table_name"

Where table_name is one of these:

packet_counts_table (number of packets sent or received to this domain. Index is domain ID)
byte_counts_table (number of bytes sent or received to this domain. Index is domain ID)
dns_total_queried (number of total dns responses that were parsed)
dns_total_missed (number of dns responses that could not be fully processed because there is not enough room in the dns responses table)

To ensure that the test was successful, if you used "smallFlows.pcap", then you should get these results when reading "dns_total_queried":
0,4,2,4,2,2,2,2,4,2,2,0,0,...
and these results when reading packet_counts_table:
0,272,34,262,104,16,20,40,88,0,26,0,0,...

When done, use "make stop" and "make clean"

Note that you can change the known domain list by editing "IWSpring2020/known_domains.txt". You can also use tcpreplay with any pcap file of your choice.

Furthermore, you can also run this exact test with "netassay_bmv2_155.p4". Just use the "netassay_bmv2_155.p4" file instead and use "IWSpring2020/knownlist_json_155.py" instead of "IWSpring2020/knownlist_json_60.py". You should
get the exact same results as above.

################### INSTRUCTIONS REGARDING PCAP ANALYSIS ###################
USAGE: pcapanalysis.py mypcapfile.pcap
where "mypcapfile.pcap" is any pcap file. This script will output statistics on:
The number of CNAME entries in DNS responses
Number of domain name requests with parts greater than 15 characters (where a domain part is defined as a part of a domain delineated by a '.')
Statistics on how many clients/packets make use of the first IP address from a DNS response
