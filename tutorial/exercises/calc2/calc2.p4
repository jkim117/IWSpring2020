#include <core.p4>
#include <v1model.p4>

#define NUM_KNOWN_DOMAINS 1024
#define NUM_KNOWN_DOMAINS_BITS 10
#define TABLE_SIZE 1024
#define HASH_TABLE_BASE 10w0
#define HASH_TABLE_MAX 10w1023
#define TIMEOUT 600000000 // 10 minutes

typedef bit<48> MacAddress;
typedef bit<32> IPv4Address;
typedef bit<128> IPv6Address;
typedef bit<32> known_domain_id;

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

header dns_q_part_1 {
    bit<8> part;
}

header dns_q_part_2 {
    bit<16> part;
}

header dns_q_part_4 {
    bit<32> part;
}

header dns_q_part_8 {
    bit<64> part;
}

header dns_q_part_16 {
    bit<128> part;
}

struct dns_qtype_class {
    bit<16> type;
    bit<16> class;
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

    dns_q_label label1;
    dns_q_part_1 q1_part1;
    dns_q_part_2 q1_part2;
    dns_q_part_4 q1_part4;
    dns_q_part_8 q1_part8;

    dns_q_label label2;
    dns_q_part_1 q2_part1;
    dns_q_part_2 q2_part2;
    dns_q_part_4 q2_part4;
    dns_q_part_8 q2_part8;
    dns_q_part_16 q2_part16;

    dns_q_label label3;
    dns_q_part_1 q3_part1;
    dns_q_part_2 q3_part2;
    dns_q_part_4 q3_part4;
    dns_q_part_8 q3_part8;
    dns_q_part_16 q3_part16;

    dns_q_label label4;
    dns_q_part_1 q4_part1;
    dns_q_part_2 q4_part2;
    dns_q_part_4 q4_part4;

    dns_q_label label5;

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

    bit<3> last_label; // Value is 1,2,3,4,5 or 0 corresponding to which dns_q_label is the last label (of value 0). If this value is 0, there is an error.
    bit<1> matched_domain;
    bit<32> domain_id;
    bit<32> index_1;
    bit<32> index_2;
    bit<32> index_3;
    bit<32> temp_timestamp; //48
    bit<32> temp_cip;
    bit<32> temp_sip;
    bit<1> already_matched;
    bit<64> min_counter;
    bit<2> min_table;
    bit<32> temp_packet_counter;
    bit<32> temp_byte_counter;

    bit<32> temp_total_dns;
    bit<32> temp_total_missed;
    bit<1> parsed_answer;
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
        user_metadata.is_dns = 0;
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

    // Parsel DNS Query Label 1
    state parse_dns_query1 {
        pkt.extract(p.label1);
        user_metadata.last_label = 1;

        transition select(p.label1.label) {
            0: parse_dns_answer;
            1: parse_dns_q1_len1;
            2: parse_dns_q1_len2;
            3: parse_dns_q1_len3;
            4: parse_dns_q1_len4;
            5: parse_dns_q1_len5;
            6: parse_dns_q1_len6;
            7: parse_dns_q1_len7;
            8: parse_dns_q1_len8;
            9: parse_dns_q1_len9;
            10: parse_dns_q1_len10;
            11: parse_dns_q1_len11;
            12: parse_dns_q1_len12;
            13: parse_dns_q1_len13;
            14: parse_dns_q1_len14;
            15: parse_dns_q1_len15;
            default: accept;
        }
    }

    state parse_dns_q1_len1 {
        pkt.extract(p.q1_part1);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len2 {
        pkt.extract(p.q1_part2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len3 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len4 {
        pkt.extract(p.q1_part4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len5 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len6 {
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len7 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len8 {
        pkt.extract(p.q1_part8);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len9 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part8);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len10 {
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part8);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len11 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part8);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len12 {
        pkt.extract(p.q1_part4);
        pkt.extract(p.q1_part8);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len13 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part4);
        pkt.extract(p.q1_part8);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len14 {
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        pkt.extract(p.q1_part8);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len15 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        pkt.extract(p.q1_part8);
        transition parse_dns_query2;
    }

    // Parsel DNS Query Label 2
    state parse_dns_query2 {
        pkt.extract(p.label2);
        user_metadata.last_label = 2;

        transition select(p.label2.label) {
            0: parse_dns_answer;
            1: parse_dns_q2_len1;
            2: parse_dns_q2_len2;
            3: parse_dns_q2_len3;
            4: parse_dns_q2_len4;
            5: parse_dns_q2_len5;
            6: parse_dns_q2_len6;
            7: parse_dns_q2_len7;
            8: parse_dns_q2_len8;
            9: parse_dns_q2_len9;
            10: parse_dns_q2_len10;
            11: parse_dns_q2_len11;
            12: parse_dns_q2_len12;
            13: parse_dns_q2_len13;
            14: parse_dns_q2_len14;
            15: parse_dns_q2_len15;
            16: parse_dns_q2_len16;
            17: parse_dns_q2_len17;
            18: parse_dns_q2_len18;
            19: parse_dns_q2_len19;
            20: parse_dns_q2_len20;
            21: parse_dns_q2_len21;
            22: parse_dns_q2_len22;
            23: parse_dns_q2_len23;
            24: parse_dns_q2_len24;
            25: parse_dns_q2_len25;
            26: parse_dns_q2_len26;
            27: parse_dns_q2_len27;
            28: parse_dns_q2_len28;
            29: parse_dns_q2_len29;
            30: parse_dns_q2_len30;
            31: parse_dns_q2_len31;
            default: accept;
        }
    }

    state parse_dns_q2_len1 {
        pkt.extract(p.q2_part1);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len2 {
        pkt.extract(p.q2_part2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len3 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len4 {
        pkt.extract(p.q2_part4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len5 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len6 {
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len7 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len8 {
        pkt.extract(p.q2_part8);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len9 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part8);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len10 {
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part8);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len11 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part8);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len12 {
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part8);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len13 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part8);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len14 {
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part8);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len15 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part8);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len16 {
        pkt.extract(p.q2_part16);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len17 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part16);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len18 {
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part16);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len19 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part16);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len20 {
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part16);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len21 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part16);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len22 {
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part16);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len23 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part16);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len24 {
        pkt.extract(p.q2_part8);
        pkt.extract(p.q2_part16);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len25 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part8);
        pkt.extract(p.q2_part16);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len26 {
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part8);
        pkt.extract(p.q2_part16);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len27 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part8);
        pkt.extract(p.q2_part16);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len28 {
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part8);
        pkt.extract(p.q2_part16);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len29 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part8);
        pkt.extract(p.q2_part16);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len30 {
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part8);
        pkt.extract(p.q2_part16);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len31 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part8);
        pkt.extract(p.q2_part16);
        transition parse_dns_query3;
    }

    // Parsel DNS Query Label 3
    state parse_dns_query3 {
        pkt.extract(p.label3);
        user_metadata.last_label = 3;

        transition select(p.label3.label) {
            0: parse_dns_answer;
            1: parse_dns_q3_len1;
            2: parse_dns_q3_len2;
            3: parse_dns_q3_len3;
            4: parse_dns_q3_len4;
            5: parse_dns_q3_len5;
            6: parse_dns_q3_len6;
            7: parse_dns_q3_len7;
            8: parse_dns_q3_len8;
            9: parse_dns_q3_len9;
            10: parse_dns_q3_len10;
            11: parse_dns_q3_len11;
            12: parse_dns_q3_len12;
            13: parse_dns_q3_len13;
            14: parse_dns_q3_len14;
            15: parse_dns_q3_len15;
            16: parse_dns_q3_len16;
            17: parse_dns_q3_len17;
            18: parse_dns_q3_len18;
            19: parse_dns_q3_len19;
            20: parse_dns_q3_len20;
            21: parse_dns_q3_len21;
            22: parse_dns_q3_len22;
            23: parse_dns_q3_len23;
            24: parse_dns_q3_len24;
            25: parse_dns_q3_len25;
            26: parse_dns_q3_len26;
            27: parse_dns_q3_len27;
            28: parse_dns_q3_len28;
            29: parse_dns_q3_len29;
            30: parse_dns_q3_len30;
            31: parse_dns_q3_len31;
            default: accept;
        }
    }

    state parse_dns_q3_len1 {
        pkt.extract(p.q3_part1);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len2 {
        pkt.extract(p.q3_part2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len3 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len4 {
        pkt.extract(p.q3_part4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len5 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len6 {
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len7 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len8 {
        pkt.extract(p.q3_part8);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len9 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part8);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len10 {
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part8);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len11 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part8);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len12 {
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part8);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len13 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part8);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len14 {
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part8);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len15 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part8);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len16 {
        pkt.extract(p.q3_part16);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len17 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part16);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len18 {
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part16);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len19 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part16);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len20 {
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part16);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len21 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part16);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len22 {
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part16);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len23 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part16);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len24 {
        pkt.extract(p.q3_part8);
        pkt.extract(p.q3_part16);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len25 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part8);
        pkt.extract(p.q3_part16);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len26 {
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part8);
        pkt.extract(p.q3_part16);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len27 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part8);
        pkt.extract(p.q3_part16);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len28 {
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part8);
        pkt.extract(p.q3_part16);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len29 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part8);
        pkt.extract(p.q3_part16);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len30 {
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part8);
        pkt.extract(p.q3_part16);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len31 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part8);
        pkt.extract(p.q3_part16);
        transition parse_dns_query4;
    }

    // Parsel DNS Query Label 4
    state parse_dns_query4 {
        pkt.extract(p.label4);
        user_metadata.last_label = 4;

        transition select(p.label4.label) {
            0: parse_dns_answer;
            1: parse_dns_q4_len1;
            2: parse_dns_q4_len2;
            3: parse_dns_q4_len3;
            4: parse_dns_q4_len4;
            5: parse_dns_q4_len5;
            6: parse_dns_q4_len6;
            7: parse_dns_q4_len7;
            default: accept;
        }
    }

    state parse_dns_q4_len1 {
        pkt.extract(p.q4_part1);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len2 {
        pkt.extract(p.q4_part2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len3 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len4 {
        pkt.extract(p.q4_part4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len5 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len6 {
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len7 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part4);
        transition parse_dns_query5;
    }

    // Parsel DNS Query Label 5
    state parse_dns_query5 {
        pkt.extract(p.label5);
        user_metadata.last_label = 5;

        transition select(p.label5.label) {
            0: parse_dns_answer;
            default: accept;
        }
    }

    state parse_dns_answer {
        pkt.extract(p.dns_answer);
        user_metadata.parsed_answer = 0;

        transition select(p.dns_answer.tc_ans.type) {
            1: set_metadata;
            default: accept;
        }
    }

    state set_metadata {
        user_metadata.parsed_answer = 1;
        transition accept;
    }
}
/**************************END OF PARSER**************************/

control TopVerifyChecksum(inout Parsed_packet headers, inout user_metadata_t user_metadata) {   
    apply {  }
}

control TopIngress(inout Parsed_packet headers,
                inout user_metadata_t user_metadata,
                inout standard_metadata_t standard_metadata) {

    // PRECISION STYLE TABLES
    register<bit<32>>(TABLE_SIZE) dns_cip_table_1;
    register<bit<32>>(TABLE_SIZE) dns_sip_table_1;
    register<bit<32>>(TABLE_SIZE) dns_name_table_1;
    register<bit<32>>(TABLE_SIZE) dns_timestamp_table_1;//48

    register<bit<32>>(TABLE_SIZE) dns_cip_table_2;
    register<bit<32>>(TABLE_SIZE) dns_sip_table_2;
    register<bit<32>>(TABLE_SIZE) dns_name_table_2;
    register<bit<32>>(TABLE_SIZE) dns_timestamp_table_2;

    register<bit<32>>(TABLE_SIZE) dns_cip_table_3;
    register<bit<32>>(TABLE_SIZE) dns_sip_table_3;
    register<bit<32>>(TABLE_SIZE) dns_name_table_3;
    register<bit<32>>(TABLE_SIZE) dns_timestamp_table_3;

    // REGISTER ARRAY FOR COLLECTING COUNTS ON TRAFFIC WITH KNOWN DOMAINS
    register<bit<32>>(NUM_KNOWN_DOMAINS) packet_counts_table;
    register<bit<32>>(NUM_KNOWN_DOMAINS) byte_counts_table;

    // REGISTER ARRAY FOR KEEPING TRACK OF OVERFLOW DNS RESPONSES
    register<bit<32>>(NUM_KNOWN_DOMAINS) dns_total_queried;
    register<bit<32>>(NUM_KNOWN_DOMAINS) dns_total_missed;

    action match_domain(known_domain_id id) {
        user_metadata.domain_id = id;
        user_metadata.matched_domain = 1;
    }

    table known_domain_list {
        key = {
            headers.q1_part1.part: exact;
            headers.q1_part2.part: exact;
            headers.q1_part4.part: exact;
            headers.q1_part8.part: exact;
            headers.q2_part1.part: exact;
            headers.q2_part2.part: exact;
            headers.q2_part4.part: exact;
            headers.q2_part8.part: exact;
            headers.q2_part16.part: exact;
            headers.q3_part1.part: exact;
            headers.q3_part2.part: exact;
            headers.q3_part4.part: exact;
            headers.q3_part8.part: exact;
            headers.q3_part16.part: exact;
            headers.q4_part1.part: exact;
            headers.q4_part2.part: exact;
            headers.q4_part4.part: exact;
        }

        actions = {
            match_domain;
            NoAction;
        }
        size = NUM_KNOWN_DOMAINS;
        default_action = NoAction();
    }

    apply {
        if(user_metadata.parsed_answer == 1) {

            user_metadata.matched_domain = 0;

            known_domain_list.apply();

            if (user_metadata.matched_domain == 1) {

                // Increment total DNS queries for this domain name
                dns_total_queried.read(user_metadata.temp_total_dns, user_metadata.domain_id);
                dns_total_queried.write(user_metadata.domain_id, user_metadata.temp_total_dns + 1);

                if (headers.dns_answer.rdata > headers.ipv4.dst) {
                    hash(user_metadata.index_1, HashAlgorithm.crc16, HASH_TABLE_BASE, {headers.dns_answer.rdata, 7w11, headers.ipv4.dst}, HASH_TABLE_MAX);
                    hash(user_metadata.index_2, HashAlgorithm.crc16, HASH_TABLE_BASE, {3w5, headers.dns_answer.rdata, 5w3, headers.ipv4.dst}, HASH_TABLE_MAX);
                    hash(user_metadata.index_3, HashAlgorithm.crc16, HASH_TABLE_BASE, {2w0, headers.dns_answer.rdata, 1w1, headers.ipv4.dst}, HASH_TABLE_MAX);
                }
                else {
                    hash(user_metadata.index_1, HashAlgorithm.crc16, HASH_TABLE_BASE, {headers.ipv4.dst, 7w11, headers.dns_answer.rdata}, HASH_TABLE_MAX);
                    hash(user_metadata.index_2, HashAlgorithm.crc16, HASH_TABLE_BASE, {3w5, headers.ipv4.dst, 5w3, headers.dns_answer.rdata}, HASH_TABLE_MAX);
                    hash(user_metadata.index_3, HashAlgorithm.crc16, HASH_TABLE_BASE, {2w0, headers.ipv4.dst, 1w1, headers.dns_answer.rdata}, HASH_TABLE_MAX);
                }

                user_metadata.already_matched = 0;
                // access table 1
                dns_cip_table_1.read(user_metadata.temp_cip, user_metadata.index_1);
                dns_sip_table_1.read(user_metadata.temp_sip, user_metadata.index_1);
                dns_timestamp_table_1.read(user_metadata.temp_timestamp, user_metadata.index_1);
                if (user_metadata.temp_timestamp == 0 || user_metadata.temp_timestamp + TIMEOUT < (bit<32>)standard_metadata.ingress_global_timestamp || (user_metadata.temp_cip == headers.ipv4.dst && user_metadata.temp_sip == headers.dns_answer.rdata)) {
                    dns_cip_table_1.write(user_metadata.index_1, headers.ipv4.dst);
                    dns_sip_table_1.write(user_metadata.index_1, headers.dns_answer.rdata);
                    dns_timestamp_table_1.write(user_metadata.index_1, (bit<32>)standard_metadata.ingress_global_timestamp);
                    dns_name_table_1.write(user_metadata.index_1, user_metadata.domain_id);
                    user_metadata.already_matched = 1;
                }

                // access table 2
                if (user_metadata.already_matched == 0) {
                    dns_cip_table_2.read(user_metadata.temp_cip, user_metadata.index_2);
                    dns_sip_table_2.read(user_metadata.temp_sip, user_metadata.index_2);
                    dns_timestamp_table_2.read(user_metadata.temp_timestamp, user_metadata.index_2);
                    if (user_metadata.temp_timestamp == 0 || user_metadata.temp_timestamp + TIMEOUT < (bit<32>)standard_metadata.ingress_global_timestamp || (user_metadata.temp_cip == headers.ipv4.dst && user_metadata.temp_sip == headers.dns_answer.rdata)) {
                        dns_cip_table_2.write(user_metadata.index_2, headers.ipv4.dst);
                        dns_sip_table_2.write(user_metadata.index_2, headers.dns_answer.rdata);
                        dns_timestamp_table_2.write(user_metadata.index_2, (bit<32>)standard_metadata.ingress_global_timestamp);
                        dns_name_table_2.write(user_metadata.index_2, user_metadata.domain_id);
                        user_metadata.already_matched = 1;
                    }
                }

                // access table 3
                if (user_metadata.already_matched == 0) {
                    dns_cip_table_3.read(user_metadata.temp_cip, user_metadata.index_3);
                    dns_sip_table_3.read(user_metadata.temp_sip, user_metadata.index_3);
                    dns_timestamp_table_3.read(user_metadata.temp_timestamp, user_metadata.index_3);
                    if (user_metadata.temp_timestamp == 0 || user_metadata.temp_timestamp + TIMEOUT < (bit<32>)standard_metadata.ingress_global_timestamp || (user_metadata.temp_cip == headers.ipv4.dst && user_metadata.temp_sip == headers.dns_answer.rdata)) {
                        dns_cip_table_3.write(user_metadata.index_3, headers.ipv4.dst);
                        dns_sip_table_3.write(user_metadata.index_3, headers.dns_answer.rdata);
                        dns_timestamp_table_3.write(user_metadata.index_3, (bit<32>)standard_metadata.ingress_global_timestamp);
                        dns_name_table_3.write(user_metadata.index_3, user_metadata.domain_id);
                        user_metadata.already_matched = 1;
                    }
                }

                if (user_metadata.already_matched == 0) {
                    // Increment total DNS queries missed for this domain name
                    dns_total_missed.read(user_metadata.temp_total_missed, user_metadata.domain_id);
                    dns_total_missed.write(user_metadata.domain_id, user_metadata.temp_total_missed + 1);
                }
            }
        }
        // HANDLE NORMAL, NON-DNS PACKETS
        else if (user_metadata.is_ip == 1 && user_metadata.is_dns == 0) {
            if (headers.ipv4.src > headers.ipv4.dst) {
                hash(user_metadata.index_1, HashAlgorithm.crc16, HASH_TABLE_BASE, {headers.ipv4.src, 7w11, headers.ipv4.dst}, HASH_TABLE_MAX);
                hash(user_metadata.index_2, HashAlgorithm.crc16, HASH_TABLE_BASE, {3w5, headers.ipv4.src, 5w3, headers.ipv4.dst}, HASH_TABLE_MAX);
                hash(user_metadata.index_3, HashAlgorithm.crc16, HASH_TABLE_BASE, {2w0, headers.ipv4.src, 1w1, headers.ipv4.dst}, HASH_TABLE_MAX);
            }
            else {
                hash(user_metadata.index_1, HashAlgorithm.crc16, HASH_TABLE_BASE, {headers.ipv4.dst, 7w11, headers.ipv4.src}, HASH_TABLE_MAX);
                hash(user_metadata.index_2, HashAlgorithm.crc16, HASH_TABLE_BASE, {3w5, headers.ipv4.dst, 5w3, headers.ipv4.src}, HASH_TABLE_MAX);
                hash(user_metadata.index_3, HashAlgorithm.crc16, HASH_TABLE_BASE, {2w0, headers.ipv4.dst, 1w1, headers.ipv4.src}, HASH_TABLE_MAX);
            }

            dns_cip_table_1.read(user_metadata.temp_cip, user_metadata.index_1);
            dns_sip_table_1.read(user_metadata.temp_sip, user_metadata.index_1);
            if ((headers.ipv4.dst == user_metadata.temp_cip && headers.ipv4.src == user_metadata.temp_sip) || (headers.ipv4.dst == user_metadata.temp_sip && headers.ipv4.src == user_metadata.temp_cip)) {
                dns_name_table_1.read(user_metadata.domain_id, user_metadata.index_1);
                packet_counts_table.read(user_metadata.temp_packet_counter, user_metadata.domain_id);
                byte_counts_table.read(user_metadata.temp_byte_counter, user_metadata.domain_id);
                packet_counts_table.write(user_metadata.domain_id, user_metadata.temp_packet_counter + 1);
                byte_counts_table.write(user_metadata.domain_id, user_metadata.temp_byte_counter + (bit<32>)headers.ipv4.len);
                dns_timestamp_table_1.write(user_metadata.index_1, (bit<32>)standard_metadata.ingress_global_timestamp);
            }

            dns_cip_table_2.read(user_metadata.temp_cip, user_metadata.index_2);
            dns_sip_table_2.read(user_metadata.temp_sip, user_metadata.index_2);
            if ((headers.ipv4.dst == user_metadata.temp_cip && headers.ipv4.src == user_metadata.temp_sip) || (headers.ipv4.dst == user_metadata.temp_sip && headers.ipv4.src == user_metadata.temp_cip)) {
                dns_name_table_2.read(user_metadata.domain_id, user_metadata.index_2);
                packet_counts_table.read(user_metadata.temp_packet_counter, user_metadata.domain_id);
                byte_counts_table.read(user_metadata.temp_byte_counter, user_metadata.domain_id);
                packet_counts_table.write(user_metadata.domain_id, user_metadata.temp_packet_counter + 1);
                byte_counts_table.write(user_metadata.domain_id, user_metadata.temp_byte_counter + (bit<32>)headers.ipv4.len);
                dns_timestamp_table_2.write(user_metadata.index_2, (bit<32>)standard_metadata.ingress_global_timestamp);
            }

            dns_cip_table_3.read(user_metadata.temp_cip, user_metadata.index_3);
            dns_sip_table_3.read(user_metadata.temp_sip, user_metadata.index_3);
            if ((headers.ipv4.dst == user_metadata.temp_cip && headers.ipv4.src == user_metadata.temp_sip) || (headers.ipv4.dst == user_metadata.temp_sip && headers.ipv4.src == user_metadata.temp_cip)) {
                dns_name_table_3.read(user_metadata.domain_id, user_metadata.index_3);
                packet_counts_table.read(user_metadata.temp_packet_counter, user_metadata.domain_id);
                byte_counts_table.read(user_metadata.temp_byte_counter, user_metadata.domain_id);
                packet_counts_table.write(user_metadata.domain_id, user_metadata.temp_packet_counter + 1);
                byte_counts_table.write(user_metadata.domain_id, user_metadata.temp_byte_counter + (bit<32>)headers.ipv4.len);
                dns_timestamp_table_3.write(user_metadata.index_3, (bit<32>)standard_metadata.ingress_global_timestamp);
            }
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
    }
}

// Instantiate the switch
V1Switch(TopParser(), TopVerifyChecksum(), TopIngress(), TopEgress(), TopComputeChecksum(), TopDeparser()) main;