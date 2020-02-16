#include <core.p4>
#include <v1model.p4>

#define TABLE_SIZE 1024
#define HASH_TABLE_BASE 10w0
#define HASH_TABLE_MAX 10w1023

typedef bit<48> MacAddress;
typedef bit<32> IPv4Address;
typedef bit<128> IPv6Address;

header ethernet_h {
    MacAddress dst;
    MacAddress src;
    bit<16> etherType; 
}
header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> tos;
    bit<16> len;
    bit<16> id;
    bit<3> flags;
    bit<13> frag;
    bit<8> ttl;
    bit<8> proto;
    bit<16> chksum;
    IPv4Address src;
    IPv4Address dst; 
}
header ipv6_h {
    bit<4> version;
    bit<8> tc;
    bit<20> fl;
    bit<16> plen;
    bit<8> nh;
    bit<8> hl;
    IPv6Address src;
    IPv6Address dst; 
}
header tcp_h {
    bit<16> sport;
    bit<16> dport;
    bit<32> seq;
    bit<32> ack;
    bit<4> dataofs;
    bit<4> reserved;
    bit<8> flags;
    bit<16> window;
    bit<16> chksum;
    bit<16> urgptr; 
}
header udp_h {
    bit<16> sport;
    bit<16> dport;
    bit<16> len;
    bit<16> chksum; 
}

header dns_h {
    bit<16> id;
    bit<1> is_response;
    bit<4> opcode;
    bit<1> auth_answer;
    bit<1> trunc;
    bit<1> recur_desired;
    bit<1> recur_avail;
    bit<1> reserved;
    bit<1> authentic_data;
    bit<1> checking_disabled;
    bit<4> resp_code;
    bit<16> q_count;
    bit<16> answer_count;
    bit<16> auth_rec;
    bit<16> addn_rec;
}

header dns_q_label {
    bit<8> label;
}

header dns_q_part {
    varbit<256> part; // For 32 bytes max
}

struct dns_qtype_class {
    bit<32> type_class;
}

struct dns_q {
    dns_q_label label1;
    dns_q_part part1;
    dns_q_label label2;
    dns_q_part part2;
    dns_q_label label3;
    dns_q_part part3;
    dns_q_label label4;
    dns_q_part part4;
    dns_q_label label5;
    bit<3> last_label; // Value is 1,2,3,4,5 or 0 corresponding to which dns_q_label is the last label (of value 0). If this value is 0, there is an error.
}

header dns_a {
    dns_qtype_class tc_query;
    bit<16> qname_pointer;
    dns_qtype_class tc_ans;
    bit<32> ttl;
    bit<16> rd_length;
    bit<32> rdata; //IPV4 is always 32 bit.
}

// List of all recognized headers
struct Parsed_packet { 
    ethernet_h ethernet;
    ipv4_h ipv4;
    udp_h udp;
    dns_h dns_header; 
    dns_q dns_query;
    dns_a dns_answer;
}

// user defined metadata: can be used to share information between
// TopParser, TopPipe, and TopDeparser 
struct user_metadata_t {
    bit<1> do_dns;
    bit<1> recur_desired;
    bit<1> response_set;
	bit<1> is_dns;
	bit<1> is_ip;
    bit<3>  unused;

    bit<1024> server_name;
    bit<64> hashed_name;
    bit<32> index_1;
    bit<32> index_2;
    bit<32> index_3;
    bit<64> temp_counter;
    bit<32> temp_cip;
    bit<32> temp_sip;
    bit<1> already_matched;
    bit<64> min_counter;
    bit<2> min_table;
}

// parsers
parser TopParser(packet_in pkt,
           out Parsed_packet p,
           inout user_metadata_t user_metadata,
           inout standard_metadata_t standard_metadata) {
    state start {
        pkt.extract(p.ethernet);
        // These are set appropriately in the TopPipe.
        user_metadata.do_dns = 0;
        user_metadata.recur_desired = 0;
        user_metadata.response_set = 0;
		user_metadata.is_dns = 0;
		user_metadata.is_ip = 0;

        transition select(p.ethernet.etherType) {
			0x800: parse_ip;
			default: accept;
		}
    }

	state parse_ip {
        pkt.extract(p.ipv4);

		user_metadata.is_ip = 1;
		transition select(p.ipv4.proto) {
			17: parse_udp;
			default: accept;
		}
	}

	state parse_udp {
        pkt.extract(p.udp);

		transition select(p.udp.dport == 53 || p.udp.sport == 53) {
			true: parse_dns_header;
			false: accept;
		}
	}

	state parse_dns_header {
        pkt.extract(p.dns_header);
		user_metadata.is_dns = 1;

		transition select(p.dns_header.is_response) {
			1: parse_dns_query1;
			default: accept;
		}
	}

    state parse_dns_query1 {
        pkt.extract(p.dns_query.label1);

        transition select(p.dns_query.label1.label) {
            0: dns_query_end1;
            default: parse_dns_query2;
        }
    }

    state dns_query_end1 {
        p.dns_query.last_label = 1;
        transition parse_dns_answer;
    }

    state parse_dns_query2 {
        bit<32> part1_size = (bit<32>)p.dns_query.label1.label;
        pkt.extract(p.dns_query.part1, part1_size << 3); // extract varbit equal to 8 times the number of bytes in label1
        pkt.extract(p.dns_query.label2);

        transition select(p.dns_query.label2.label) {
            0: dns_query_end2;
            default: parse_dns_query3;
        }
    }

    state dns_query_end2 {
        p.dns_query.last_label = 2;
        transition parse_dns_answer;
    }

    state parse_dns_query3 {
        bit<32> part2_size = (bit<32>)p.dns_query.label2.label;
        pkt.extract(p.dns_query.part2, part2_size << 3); // extract varbit equal to 8 times the number of bytes in label2
        pkt.extract(p.dns_query.label3);

        transition select(p.dns_query.label3.label) {
            0: dns_query_end3;
            default: parse_dns_query4;
        }
    }

    state dns_query_end3 {
        p.dns_query.last_label = 3;
        transition parse_dns_answer;
    }

    state parse_dns_query4 {
        bit<32> part3_size = (bit<32>)p.dns_query.label3.label;
        pkt.extract(p.dns_query.part3, part3_size << 3); // extract varbit equal to 8 times the number of bytes in label3
        pkt.extract(p.dns_query.label4);

        transition select(p.dns_query.label4.label) {
            0: dns_query_end4;
            default: parse_dns_query5;
        }
    }

    state dns_query_end4 {
        p.dns_query.last_label = 4;
        transition parse_dns_answer;
    }

    state parse_dns_query5 {
        bit<32> part4_size = (bit<32>)p.dns_query.label4.label;
        pkt.extract(p.dns_query.part4, part4_size << 3); // extract varbit equal to 8 times the number of bytes in label4
        pkt.extract(p.dns_query.label5);

        transition select(p.dns_query.label5.label) {
            0: dns_query_end5;
            default: domain_too_long;
        }
    }

    state dns_query_end5 {
        p.dns_query.last_label = 5;
        transition parse_dns_answer;
    }

    state domain_too_long {
        p.dns_query.last_label = 0;
        transition accept;
    }

    state parse_dns_answer {
        pkt.extract(p.dns_answer);

        transition accept;
    }
}

control TopVerifyChecksum(inout Parsed_packet headers, inout user_metadata_t user_metadata) {   
    apply {  }
}

control TopIngress(inout Parsed_packet headers,
                inout user_metadata_t user_metadata,
                inout standard_metadata_t standard_metadata) {

    register<bit<32>>(TABLE_SIZE) dns_cip_table_1;
    register<bit<32>>(TABLE_SIZE) dns_sip_table_1;
    register<bit<64>>(TABLE_SIZE) dns_hashed_name_table_1;
    register<bit<64>>(TABLE_SIZE) dns_counter_table_1;

    register<bit<32>>(TABLE_SIZE) dns_cip_table_2;
    register<bit<32>>(TABLE_SIZE) dns_sip_table_2;
    register<bit<64>>(TABLE_SIZE) dns_hashed_name_table_2;
    register<bit<64>>(TABLE_SIZE) dns_counter_table_2;

    register<bit<32>>(TABLE_SIZE) dns_cip_table_3;
    register<bit<32>>(TABLE_SIZE) dns_sip_table_3;
    register<bit<64>>(TABLE_SIZE) dns_hashed_name_table_3;
    register<bit<64>>(TABLE_SIZE) dns_counter_table_3;

    action add_domain_entry() {
        bit<64> NAME_HASH_MIN = 64w0;
        bit<64> NAME_HASH_MAX = 0xffffffffffffffff;

        if (headers.dns_query.last_label == 1) {
            hash(user_metadata.hashed_name, HashAlgorithm.crc16, NAME_HASH_MIN, {headers.dns_query.label1.label}, NAME_HASH_MAX);
        } else if (headers.dns_query.last_label == 2) {
            hash(user_metadata.hashed_name, HashAlgorithm.crc16, NAME_HASH_MIN, {headers.dns_query.label1.label, headers.dns_query.part1.part, headers.dns_query.label2.label}, NAME_HASH_MAX);
        } else if (headers.dns_query.last_label == 3) {
            hash(user_metadata.hashed_name, HashAlgorithm.crc16, NAME_HASH_MIN, {headers.dns_query.label1.label, headers.dns_query.part1.part, headers.dns_query.label2.label, headers.dns_query.part2.part, headers.dns_query.label3.label}, NAME_HASH_MAX);
        } else if (headers.dns_query.last_label == 4) {
            hash(user_metadata.hashed_name, HashAlgorithm.crc16, NAME_HASH_MIN, {headers.dns_query.label1.label, headers.dns_query.part1.part, headers.dns_query.label2.label, headers.dns_query.part2.part, headers.dns_query.label3.label, headers.dns_query.part3.part, headers.dns_query.label4.label}, NAME_HASH_MAX);
        } else if (headers.dns_query.last_label == 5) {
            hash(user_metadata.hashed_name, HashAlgorithm.crc16, NAME_HASH_MIN, {headers.dns_query.label1.label, headers.dns_query.part1.part, headers.dns_query.label2.label, headers.dns_query.part2.part, headers.dns_query.label3.label, headers.dns_query.part3.part, headers.dns_query.label4.label, headers.dns_query.part4.part, headers.dns_query.label5.label}, NAME_HASH_MAX);
        }

        // headers.dns_answer.rdata; server ip
        // headers.ipv4.dst; client ip

        hash(user_metadata.index_1, HashAlgorithm.crc16, HASH_TABLE_BASE, {headers.dns_answer.rdata, 7w11, headers.ipv4.dst}, HASH_TABLE_MAX);
        hash(user_metadata.index_2, HashAlgorithm.crc16, HASH_TABLE_BASE, {3w5, headers.dns_answer.rdata, 5w3, headers.ipv4.dst}, HASH_TABLE_MAX);
        hash(user_metadata.index_3, HashAlgorithm.crc16, HASH_TABLE_BASE, {2w0, headers.dns_answer.rdata, 1w1, headers.ipv4.dst}, HASH_TABLE_MAX);

        user_metadata.already_matched = 0;
        // access table 1
        dns_cip_table_1.read(user_metadata.temp_cip, user_metadata.index_1);
        dns_sip_table_1.read(user_metadata.temp_sip, user_metadata.index_1);
        dns_counter_table_1.read(user_metadata.temp_counter, user_metadata.index_1);
        if (user_metadata.temp_counter == 0 || (user_metadata.temp_cip == headers.ipv4.dst && user_metadata.temp_sip == headers.dns_answer.rdata)) {
            dns_cip_table_1.write(user_metadata.index_1, headers.ipv4.dst);
            dns_sip_table_1.write(user_metadata.index_1, headers.dns_answer.rdata);
            dns_counter_table_1.write(user_metadata.index_1, user_metadata.temp_counter + 1);
            dns_hashed_name_table_1.write(user_metadata.index_1, user_metadata.hashed_name);
            user_metadata.already_matched = 1;
        }
        else {
            user_metadata.min_counter = user_metadata.temp_counter;
            user_metadata.min_table = 1;
        }

        // access table 2
        if (user_metadata.already_matched == 0) {
            dns_cip_table_2.read(user_metadata.temp_cip, user_metadata.index_2);
            dns_sip_table_2.read(user_metadata.temp_sip, user_metadata.index_2);
            dns_counter_table_2.read(user_metadata.temp_counter, user_metadata.index_2);
            if (user_metadata.temp_counter == 0 || (user_metadata.temp_cip == headers.ipv4.dst && user_metadata.temp_sip == headers.dns_answer.rdata)) {
                dns_cip_table_2.write(user_metadata.index_2, headers.ipv4.dst);
                dns_sip_table_2.write(user_metadata.index_2, headers.dns_answer.rdata);
                dns_counter_table_2.write(user_metadata.index_2, user_metadata.temp_counter + 1);
                dns_hashed_name_table_2.write(user_metadata.index_2, user_metadata.hashed_name);
                user_metadata.already_matched = 1;
            }
            else {
                if (user_metadata.temp_counter < user_metadata.min_counter) {
                    user_metadata.min_counter = user_metadata.temp_counter;
                    user_metadata.min_table = 2;
                }
            }
        }

        // access table 3
        if (user_metadata.already_matched == 0) {
            dns_cip_table_3.read(user_metadata.temp_cip, user_metadata.index_3);
            dns_sip_table_3.read(user_metadata.temp_sip, user_metadata.index_3);
            dns_counter_table_3.read(user_metadata.temp_counter, user_metadata.index_3);
            if (user_metadata.temp_counter == 0 || (user_metadata.temp_cip == headers.ipv4.dst && user_metadata.temp_sip == headers.dns_answer.rdata)) {
                dns_cip_table_3.write(user_metadata.index_3, headers.ipv4.dst);
                dns_sip_table_3.write(user_metadata.index_3, headers.dns_answer.rdata);
                dns_counter_table_3.write(user_metadata.index_3, user_metadata.temp_counter + 1);
                dns_hashed_name_table_3.write(user_metadata.index_3, user_metadata.hashed_name);
                user_metadata.already_matched = 1;
            }
            else {
                if (user_metadata.temp_counter < user_metadata.min_counter) {
                    user_metadata.min_counter = user_metadata.temp_counter;
                    user_metadata.min_table = 3;
                }
            }
        }

        // recirculate
        if (user_metadata.already_matched == 0) {
            if(user_metadata.min_table == 1) {
                dns_cip_table_1.write(user_metadata.index_1, headers.ipv4.dst);
                dns_sip_table_1.write(user_metadata.index_1, headers.dns_answer.rdata);
                dns_counter_table_1.write(user_metadata.index_1, 1);
                dns_hashed_name_table_1.write(user_metadata.index_1, user_metadata.hashed_name);
            }
            else if (user_metadata.min_table == 2) {
                dns_cip_table_2.write(user_metadata.index_2, headers.ipv4.dst);
                dns_sip_table_2.write(user_metadata.index_2, headers.dns_answer.rdata);
                dns_counter_table_2.write(user_metadata.index_2, 1);
                dns_hashed_name_table_2.write(user_metadata.index_2, user_metadata.hashed_name);
            }
            else if (user_metadata.min_table == 3) {
                dns_cip_table_3.write(user_metadata.index_3, headers.ipv4.dst);
                dns_sip_table_3.write(user_metadata.index_3, headers.dns_answer.rdata);
                dns_counter_table_3.write(user_metadata.index_3, 1);
                dns_hashed_name_table_3.write(user_metadata.index_3, user_metadata.hashed_name);
            }
        }

    }

    table known_domain_list {
        key = {user_metadata.server_name: exact;}

        actions = {
            add_domain_entry;
            NoAction;
        }
        size = 2048; //tbd
        default_action = NoAction();
    }

    apply {
        bit<1024> SERVER_MIN = 0;
        bit<1024> SERVER_MAX = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
        if(headers.dns_answer.isValid()) {
            if (headers.dns_query.last_label == 1) {
                hash(user_metadata.server_name, HashAlgorithm.identity, SERVER_MIN, {headers.dns_query.label1.label}, SERVER_MAX);
            } else if (headers.dns_query.last_label == 2) {
                hash(user_metadata.server_name, HashAlgorithm.identity, SERVER_MIN, {headers.dns_query.label1.label, headers.dns_query.part1.part, headers.dns_query.label2.label}, SERVER_MAX);
            } else if (headers.dns_query.last_label == 3) {
                hash(user_metadata.server_name, HashAlgorithm.identity, SERVER_MIN, {headers.dns_query.label1.label, headers.dns_query.part1.part, headers.dns_query.label2.label, headers.dns_query.part2.part, headers.dns_query.label3.label}, SERVER_MAX);
            } else if (headers.dns_query.last_label == 4) {
                hash(user_metadata.server_name, HashAlgorithm.identity, SERVER_MIN, {headers.dns_query.label1.label, headers.dns_query.part1.part, headers.dns_query.label2.label, headers.dns_query.part2.part, headers.dns_query.label3.label, headers.dns_query.part3.part, headers.dns_query.label4.label}, SERVER_MAX);
            } else if (headers.dns_query.last_label == 5) {
                hash(user_metadata.server_name, HashAlgorithm.identity, SERVER_MIN, {headers.dns_query.label1.label, headers.dns_query.part1.part, headers.dns_query.label2.label, headers.dns_query.part2.part, headers.dns_query.label3.label, headers.dns_query.part3.part, headers.dns_query.label4.label, headers.dns_query.part4.part, headers.dns_query.label5.label}, SERVER_MAX);
            }

            known_domain_list.apply();
        }
	}
}

control TopEgress(inout Parsed_packet headers,
                 inout user_metadata_t user_metadata,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

control TopComputeChecksum(inout Parsed_packet headers, inout user_metadata_t user_metadata) {
    apply {
	update_checksum(
	    headers.ipv4.isValid(),
            {
                headers.ipv4.version,
                headers.ipv4.ihl,
                headers.ipv4.tos,
                headers.ipv4.len,
                headers.ipv4.id,
                headers.ipv4.flags,
                headers.ipv4.frag,
                headers.ipv4.ttl,
                headers.ipv4.proto,
                headers.ipv4.src,
                headers.ipv4.dst
            },
            headers.ipv4.chksum,
            HashAlgorithm.csum16);
    }
}

// Deparser Implementation
control TopDeparser(packet_out b,
                    in Parsed_packet p) { 
    apply {
        /*b.emit(p.ethernet);
        b.emit(p.ipv4);
        b.emit(p.udp);
        b.emit(p.dns.dns_header);
		// Only one of these can ever be valid at once.  See the end of
		// the top pipe.
        b.emit(p.dns.question);
		b.emit(p.question_48);
        b.emit(p.dns_response_fields);*/
    }
}

// Instantiate the switch
V1Switch(TopParser(), TopVerifyChecksum(), TopIngress(), TopEgress(), TopComputeChecksum(), TopDeparser()) main;