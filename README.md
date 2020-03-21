# IWSpring2020

proto1.p4 -> uses exact matching. Assumes IP entry is the first entry in the DNS response answer. This does work in BMV2 currently.
proto2.p4 -> uses ternary matching. Able to parse variable number of CNAME entries that may precede an IP entry in a DNS response. This does not work in BMV2 currently due to ternary matching issues.

################### INSTRUCTIONS TO RUN PROTO1.P4 ###################

All tests were run through the P4 Tutorial Virtual Machine using VirtualBox.

First, download the repo from GitHub: https://github.com/jkim117/IWSpring2020

cd into IWSpring2020/tutorial/exercises/calc2

Note that calc2.p4 is just a copy of proto1.p4

Next, type: "make run"

Once Mininet is running, type "xterm h1"

In the new terminal, cd to a directory with the pcap file of your choice and execute:

"tcpreplay -i eth0 myfile.pcap"

Now, in the main terminal running Mininet, type "xterm s1"

In that new terminal type "simple_switch_CLI"

Then type: "register_read table_name"

Where table_name is one of these:

packet_counts_table (number of packets sent or received to this domain. Index is domain ID)
byte_counts_table (number of bytes sent or received to this domain. Index is domain ID)
dns_total_queried (number of total dns responses that were parsed)
dns_total_missed (number of dns responses that could not be fully processed because there is not enough room in the dns responses table)

When done, use "make stop" and "make clean"

################### INSTRUCTIONS REGARDING KNOWN LIST CREATION ###################

top500Domains.csv taken from https://moz.com/top500

createknownlist.py takes the csv file and outputs known_domains.txt

knownlist_json.py takes known_domains.txt and outputs s1-runtime.json which includes entries for the match action table

################### INSTRUCTIONS REGARDING PCAP ANALYSIS ###################
USAGE: pcapanalysis.py mypcapfile.pcap
where "mypcapfile.pcap" is any pcap file. This script will output statistics on:
The number of CNAME entries in DNS responses
Number of domain name requests with parts greater than 15 characters (where a domain part is defined as a part of a domain delineated by a '.')
Statistics on how many clients/packets make use of the first IP address from a DNS response

