#include <core.p4>
#include <v1model.p4>

#define NUM_BANNED_DST_IP 100
#define NUM_ALLOWABLE_DST_IP 100
#define NUM_KNOWN_DOMAINS 2048
#define NUM_KNOWN_DOMAINS_BITS 10
#define TABLE_SIZE 16384
#define HASH_TABLE_BASE 14w0
#define HASH_TABLE_MAX 14w16383
#define TIMEOUT 300000000 // 5 minutes

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

struct dns_qtype_class {
    bit<16> type;
    bit<16> class;
}

header dns_query_tc{
    dns_qtype_class tc_query;
}

header dns_a {
    bit<16> qname_pointer;
    dns_qtype_class tc_ans;
    bit<32> ttl;
    bit<16> rd_length;
}

header dns_a_ip {
    bit<32> rdata; //IPV4 is always 32 bit.
}

header tls_h {
    bit<8> contenttype;
    bit<16> version;
    bit<16> tlslength;
    bit<8> handshaketype;
    bit<24> handshakelength;
    bit<16> clientversion;
    bit<256> clientrandom;
    bit<8> sessionidlength;
}

header tlsciphersuite_h {
    bit<16> ciphersuitelength;
}

header tlscompressionmethods_h {
    bit<8> compressionmethodslength;
}

header tlsextension_h {
    bit<16> type;
    bit<16> extensionlength;
}

header tlsdomain_h {
    bit<16> entrylength;
    bit<8> entrytype;
    bit<16> domainlength;
}

header domain_byte {
    bit<8> char;
}

// List of all recognized headers
struct Parsed_packet { 
    ethernet_h ethernet;
    ipv4_h ipv4;
    udp_h udp;
    dns_h dns_header;

    tcp_h tcp;
    tls_h tls;
    tlsciphersuite_h tlscipher;
    tlscompressionmethods_h tlscompression;
    tlsextension_h tlsextension;
    tlsdomain_h tlsdomainheader;

    domain_byte q1_1;
    domain_byte q1_2;
    domain_byte q1_3;
    domain_byte q1_4;
    domain_byte q1_5;
    domain_byte q1_6;
    domain_byte q1_7;
    domain_byte q1_8;
    domain_byte q1_9;
    domain_byte q1_10;
    domain_byte q1_11;
    domain_byte q1_12;
    domain_byte q1_13;
    domain_byte q1_14;
    domain_byte q1_15;
    domain_byte q1_16;
    domain_byte q1_17;
    domain_byte q1_18;
    domain_byte q1_19;
    domain_byte q1_20;
    domain_byte q1_21;
    domain_byte q1_22;
    domain_byte q1_23;
    domain_byte q1_24;
    domain_byte q1_25;
    domain_byte q1_26;
    domain_byte q1_27;
    domain_byte q1_28;
    domain_byte q1_29;
    domain_byte q1_30;
    domain_byte q1_31;
    domain_byte q1_32;

    domain_byte q2_1;
    domain_byte q2_2;
    domain_byte q2_3;
    domain_byte q2_4;
    domain_byte q2_5;
    domain_byte q2_6;
    domain_byte q2_7;
    domain_byte q2_8;
    domain_byte q2_9;
    domain_byte q2_10;
    domain_byte q2_11;
    domain_byte q2_12;
    domain_byte q2_13;
    domain_byte q2_14;
    domain_byte q2_15;
    domain_byte q2_16;
    domain_byte q2_17;
    domain_byte q2_18;
    domain_byte q2_19;
    domain_byte q2_20;
    domain_byte q2_21;
    domain_byte q2_22;
    domain_byte q2_23;
    domain_byte q2_24;
    domain_byte q2_25;
    domain_byte q2_26;
    domain_byte q2_27;
    domain_byte q2_28;
    domain_byte q2_29;
    domain_byte q2_30;
    domain_byte q2_31;
    domain_byte q2_32;

    domain_byte q3_1;
    domain_byte q3_2;
    domain_byte q3_3;
    domain_byte q3_4;
    domain_byte q3_5;
    domain_byte q3_6;
    domain_byte q3_7;
    domain_byte q3_8;
    domain_byte q3_9;
    domain_byte q3_10;
    domain_byte q3_11;
    domain_byte q3_12;
    domain_byte q3_13;
    domain_byte q3_14;
    domain_byte q3_15;
    domain_byte q3_16;
    domain_byte q3_17;
    domain_byte q3_18;
    domain_byte q3_19;
    domain_byte q3_20;
    domain_byte q3_21;
    domain_byte q3_22;
    domain_byte q3_23;
    domain_byte q3_24;
    domain_byte q3_25;
    domain_byte q3_26;
    domain_byte q3_27;
    domain_byte q3_28;
    domain_byte q3_29;
    domain_byte q3_30;
    domain_byte q3_31;
    domain_byte q3_32;

    domain_byte q4_1;
    domain_byte q4_2;
    domain_byte q4_3;
    domain_byte q4_4;
    domain_byte q4_5;
    domain_byte q4_6;
    domain_byte q4_7;
    domain_byte q4_8;
    domain_byte q4_9;
    domain_byte q4_10;
    domain_byte q4_11;
    domain_byte q4_12;
    domain_byte q4_13;
    domain_byte q4_14;
    domain_byte q4_15;
    domain_byte q4_16;
    domain_byte q4_17;
    domain_byte q4_18;
    domain_byte q4_19;
    domain_byte q4_20;
    domain_byte q4_21;
    domain_byte q4_22;
    domain_byte q4_23;
    domain_byte q4_24;
    domain_byte q4_25;
    domain_byte q4_26;
    domain_byte q4_27;
    domain_byte q4_28;
    domain_byte q4_29;
    domain_byte q4_30;
    domain_byte q4_31;
    domain_byte q4_32;

    domain_byte q5_1;
    domain_byte q5_2;
    domain_byte q5_3;
    domain_byte q5_4;
    domain_byte q5_5;
    domain_byte q5_6;
    domain_byte q5_7;
    domain_byte q5_8;
    domain_byte q5_9;
    domain_byte q5_10;
    domain_byte q5_11;
    domain_byte q5_12;
    domain_byte q5_13;
    domain_byte q5_14;
    domain_byte q5_15;
    domain_byte q5_16;
    domain_byte q5_17;
    domain_byte q5_18;
    domain_byte q5_19;
    domain_byte q5_20;
    domain_byte q5_21;
    domain_byte q5_22;
    domain_byte q5_23;
    domain_byte q5_24;
    domain_byte q5_25;
    domain_byte q5_26;
    domain_byte q5_27;
    domain_byte q5_28;
    domain_byte q5_29;
    domain_byte q5_30;
    domain_byte q5_31;

    dns_q_label label1;
    dns_q_part_1 q1_part1;
    dns_q_part_2 q1_part2;
    dns_q_part_4 q1_part4;
    dns_q_part_4 q1_part8_1;
    dns_q_part_4 q1_part8_2;
    dns_q_part_4 q1_part16_1;
    dns_q_part_4 q1_part16_2;
    dns_q_part_4 q1_part16_3;
    dns_q_part_4 q1_part16_4;

    dns_q_label label2;
    dns_q_part_1 q2_part1;
    dns_q_part_2 q2_part2;
    dns_q_part_4 q2_part4;
    dns_q_part_4 q2_part8_1;
    dns_q_part_4 q2_part8_2;
    dns_q_part_4 q2_part16_1;
    dns_q_part_4 q2_part16_2;
    dns_q_part_4 q2_part16_3;
    dns_q_part_4 q2_part16_4;

    dns_q_label label3;
    dns_q_part_1 q3_part1;
    dns_q_part_2 q3_part2;
    dns_q_part_4 q3_part4;
    dns_q_part_4 q3_part8_1;
    dns_q_part_4 q3_part8_2;
    dns_q_part_4 q3_part16_1;
    dns_q_part_4 q3_part16_2;
    dns_q_part_4 q3_part16_3;
    dns_q_part_4 q3_part16_4;

    dns_q_label label4;
    dns_q_part_1 q4_part1;
    dns_q_part_2 q4_part2;
    dns_q_part_4 q4_part4;
    dns_q_part_4 q4_part8_1;
    dns_q_part_4 q4_part8_2;
    dns_q_part_4 q4_part16_1;
    dns_q_part_4 q4_part16_2;
    dns_q_part_4 q4_part16_3;
    dns_q_part_4 q4_part16_4;

    dns_q_label label5;
    dns_q_part_1 q5_part1;
    dns_q_part_2 q5_part2;
    dns_q_part_4 q5_part4;
    dns_q_part_4 q5_part8_1;
    dns_q_part_4 q5_part8_2;
    dns_q_part_4 q5_part16_1;
    dns_q_part_4 q5_part16_2;
    dns_q_part_4 q5_part16_3;
    dns_q_part_4 q5_part16_4;

    dns_q_label label6;

    dns_query_tc query_tc;

    dns_a dns_answer;
    dns_a_ip dns_ip;
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

    bit<1> is_clienthello;
    bit<1> domain_parsed;
    bit<16> domain_chars_parsed;

    bit<3> last_label; // Value is 1,2,3,4,5 or 0 corresponding to which dns_q_label is the last label (of value 0). If this value is 0, there is an error.
    bit<1> matched_domain;

    bit<32> q1_id;
    bit<32> q2_id;
    bit<32> q3_id;
    bit<32> q4_id;
    bit<32> q5_id;
    bit<32> domain_id;

    bit<32> index_1;
    bit<32> index_2;
    bit<32> index_3;
    bit<32> index_4;
    bit<32> temp_timestamp;
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
        user_metadata.is_clienthello = 0;
        user_metadata.domain_parsed = 0;

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
            6: parse_tls;
			default: accept;
		}
	}

    state parse_tls {
        pkt.extract(p.tcp);
        pkt.extract(p.tls);

		transition select(p.tls.handshaketype == 1 && p.tls.contenttype == 22) { // 1 refers to client hello
            true: parse_tls_extra;
            false: accept;
		}
	}

    state parse_tls_extra {
        user_metadata.is_clienthello = 1;

        pkt.advance( 8 * (bit<32>) (p.tls.sessionidlength));
        pkt.extract(p.tlscipher);
        pkt.advance(8 * (bit<32>) (p.tlscipher.ciphersuitelength));
        pkt.extract(p.tlscompression);
        pkt.advance(8 * (bit<32>) (p.tlscompression.compressionmethodslength));

        pkt.advance(16); // length of extension fields. Value not needed

        transition parse_extension;
    }

    state parse_extension {
        pkt.extract(p.tlsextension);

        transition select(p.tlsextension.type) {
            0: parse_domain;
            default: parse_otherextension;
        }
    }

    state parse_otherextension {
        pkt.advance(8 * (bit<32>) (p.tlsextension.extensionlength));

        transition parse_extension;
    }

    state parse_domain {
        pkt.extract(p.tlsdomainheader);

        transition select(p.tlsdomainheader.entrytype) {
            0: parse_domain_name;
            default: accept;
        }
    }

    state parse_domain_name {
        user_metadata.domain_parsed = 1;
        user_metadata.domain_chars_parsed = 0;

        p.q1_1.char = 0;
        p.q1_2.char = 0;
        p.q1_3.char = 0;
        p.q1_4.char = 0;
        p.q1_5.char = 0;
        p.q1_6.char = 0;
        p.q1_7.char = 0;
        p.q1_8.char = 0;
        p.q1_9.char = 0;
        p.q1_10.char = 0;
        p.q1_11.char = 0;
        p.q1_12.char = 0;
        p.q1_13.char = 0;
        p.q1_14.char = 0;
        p.q1_15.char = 0;
        p.q1_16.char = 0;
        p.q1_17.char = 0;
        p.q1_18.char = 0;
        p.q1_19.char = 0;
        p.q1_20.char = 0;
        p.q1_21.char = 0;
        p.q1_22.char = 0;
        p.q1_23.char = 0;
        p.q1_24.char = 0;
        p.q1_25.char = 0;
        p.q1_26.char = 0;
        p.q1_27.char = 0;
        p.q1_28.char = 0;
        p.q1_29.char = 0;
        p.q1_30.char = 0;
        p.q1_31.char = 0;
        p.q1_32.char = 0;

        p.q2_1.char = 0;
        p.q2_2.char = 0;
        p.q2_3.char = 0;
        p.q2_4.char = 0;
        p.q2_5.char = 0;
        p.q2_6.char = 0;
        p.q2_7.char = 0;
        p.q2_8.char = 0;
        p.q2_9.char = 0;
        p.q2_10.char = 0;
        p.q2_11.char = 0;
        p.q2_12.char = 0;
        p.q2_13.char = 0;
        p.q2_14.char = 0;
        p.q2_15.char = 0;
        p.q2_16.char = 0;
        p.q2_17.char = 0;
        p.q2_18.char = 0;
        p.q2_19.char = 0;
        p.q2_20.char = 0;
        p.q2_21.char = 0;
        p.q2_22.char = 0;
        p.q2_23.char = 0;
        p.q2_24.char = 0;
        p.q2_25.char = 0;
        p.q2_26.char = 0;
        p.q2_27.char = 0;
        p.q2_28.char = 0;
        p.q2_29.char = 0;
        p.q2_30.char = 0;
        p.q2_31.char = 0;
        p.q2_32.char = 0;

        p.q3_1.char = 0;
        p.q3_2.char = 0;
        p.q3_3.char = 0;
        p.q3_4.char = 0;
        p.q3_5.char = 0;
        p.q3_6.char = 0;
        p.q3_7.char = 0;
        p.q3_8.char = 0;
        p.q3_9.char = 0;
        p.q3_10.char = 0;
        p.q3_11.char = 0;
        p.q3_12.char = 0;
        p.q3_13.char = 0;
        p.q3_14.char = 0;
        p.q3_15.char = 0;
        p.q3_16.char = 0;
        p.q3_17.char = 0;
        p.q3_18.char = 0;
        p.q3_19.char = 0;
        p.q3_20.char = 0;
        p.q3_21.char = 0;
        p.q3_22.char = 0;
        p.q3_23.char = 0;
        p.q3_24.char = 0;
        p.q3_25.char = 0;
        p.q3_26.char = 0;
        p.q3_27.char = 0;
        p.q3_28.char = 0;
        p.q3_29.char = 0;
        p.q3_30.char = 0;
        p.q3_31.char = 0;
        p.q3_32.char = 0;

        p.q4_1.char = 0;
        p.q4_2.char = 0;
        p.q4_3.char = 0;
        p.q4_4.char = 0;
        p.q4_5.char = 0;
        p.q4_6.char = 0;
        p.q4_7.char = 0;
        p.q4_8.char = 0;
        p.q4_9.char = 0;
        p.q4_10.char = 0;
        p.q4_11.char = 0;
        p.q4_12.char = 0;
        p.q4_13.char = 0;
        p.q4_14.char = 0;
        p.q4_15.char = 0;
        p.q4_16.char = 0;
        p.q4_17.char = 0;
        p.q4_18.char = 0;
        p.q4_19.char = 0;
        p.q4_20.char = 0;
        p.q4_21.char = 0;
        p.q4_22.char = 0;
        p.q4_23.char = 0;
        p.q4_24.char = 0;
        p.q4_25.char = 0;
        p.q4_26.char = 0;
        p.q4_27.char = 0;
        p.q4_28.char = 0;
        p.q4_29.char = 0;
        p.q4_30.char = 0;
        p.q4_31.char = 0;
        p.q4_32.char = 0;

        p.q5_1.char = 0;
        p.q5_2.char = 0;
        p.q5_3.char = 0;
        p.q5_4.char = 0;
        p.q5_5.char = 0;
        p.q5_6.char = 0;
        p.q5_7.char = 0;
        p.q5_8.char = 0;
        p.q5_9.char = 0;
        p.q5_10.char = 0;
        p.q5_11.char = 0;
        p.q5_12.char = 0;
        p.q5_13.char = 0;
        p.q5_14.char = 0;
        p.q5_15.char = 0;
        p.q5_16.char = 0;
        p.q5_17.char = 0;
        p.q5_18.char = 0;
        p.q5_19.char = 0;
        p.q5_20.char = 0;
        p.q5_21.char = 0;
        p.q5_22.char = 0;
        p.q5_23.char = 0;
        p.q5_24.char = 0;
        p.q5_25.char = 0;
        p.q5_26.char = 0;
        p.q5_27.char = 0;
        p.q5_28.char = 0;
        p.q5_29.char = 0;
        p.q5_30.char = 0;
        p.q5_31.char = 0;

        transition parse_q1_1;
    }

    state parse_q1_1 {
        pkt.extract(p.q1_1);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_1.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_2;
        }
    }
    state parse_q1_2 {
        pkt.extract(p.q1_2);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_2.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_3;
        }
    }
    state parse_q1_3 {
        pkt.extract(p.q1_3);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_3.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_4;
        }
    }
    state parse_q1_4 {
        pkt.extract(p.q1_4);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_4.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_5;
        }
    }
    state parse_q1_5 {
        pkt.extract(p.q1_5);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_5.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_6;
        }
    }
    state parse_q1_6 {
        pkt.extract(p.q1_6);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_6.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_7;
        }
    }
    state parse_q1_7 {
        pkt.extract(p.q1_7);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_7.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_8;
        }
    }
    state parse_q1_8 {
        pkt.extract(p.q1_8);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_8.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_9;
        }
    }
    state parse_q1_9 {
        pkt.extract(p.q1_9);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_9.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_10;
        }
    }
    state parse_q1_10 {
        pkt.extract(p.q1_10);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_10.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_11;
        }
    }
    state parse_q1_11 {
        pkt.extract(p.q1_11);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_11.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_12;
        }
    }
    state parse_q1_12 {
        pkt.extract(p.q1_12);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_12.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_13;
        }
    }
    state parse_q1_13 {
        pkt.extract(p.q1_13);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_13.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_14;
        }
    }
    state parse_q1_14 {
        pkt.extract(p.q1_14);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_14.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_15;
        }
    }
    state parse_q1_15 {
        pkt.extract(p.q1_15);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_15.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_16;
        }
    }
    state parse_q1_16 {
        pkt.extract(p.q1_16);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_16.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_17;
        }
    }
    state parse_q1_17 {
        pkt.extract(p.q1_17);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_17.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_18;
        }
    }
    state parse_q1_18 {
        pkt.extract(p.q1_18);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_18.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_19;
        }
    }
    state parse_q1_19 {
        pkt.extract(p.q1_19);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_19.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_20;
        }
    }
    state parse_q1_20 {
        pkt.extract(p.q1_20);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_20.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_21;
        }
    }
    state parse_q1_21 {
        pkt.extract(p.q1_21);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_21.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_22;
        }
    }
    state parse_q1_22 {
        pkt.extract(p.q1_22);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_22.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_23;
        }
    }
    state parse_q1_23 {
        pkt.extract(p.q1_23);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_23.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_24;
        }
    }
    state parse_q1_24 {
        pkt.extract(p.q1_24);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_24.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_25;
        }
    }
    state parse_q1_25 {
        pkt.extract(p.q1_25);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_25.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_26;
        }
    }
    state parse_q1_26 {
        pkt.extract(p.q1_26);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_26.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_27;
        }
    }
    state parse_q1_27 {
        pkt.extract(p.q1_27);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_27.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_28;
        }
    }
    state parse_q1_28 {
        pkt.extract(p.q1_28);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_28.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_29;
        }
    }
    state parse_q1_29 {
        pkt.extract(p.q1_29);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_29.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_30;
        }
    }
    state parse_q1_30 {
        pkt.extract(p.q1_30);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_30.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_31;
        }
    }
    state parse_q1_31 {
        pkt.extract(p.q1_31);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_31.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_32;
        }
    }
    state parse_q1_32 {
        pkt.extract(p.q1_32);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_32.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_failure;
        }
    }
    state parse_q1_end {
        transition select(user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: accept;
            false: parse_q2_1;
        }
    }

    state parse_q2_1 {
        pkt.extract(p.q2_1);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_1.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_2;
        }
    }
    state parse_q2_2 {
        pkt.extract(p.q2_2);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_2.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_3;
        }
    }
    state parse_q2_3 {
        pkt.extract(p.q2_3);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_3.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_4;
        }
    }
    state parse_q2_4 {
        pkt.extract(p.q2_4);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_4.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_5;
        }
    }
    state parse_q2_5 {
        pkt.extract(p.q2_5);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_5.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_6;
        }
    }
    state parse_q2_6 {
        pkt.extract(p.q2_6);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_6.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_7;
        }
    }
    state parse_q2_7 {
        pkt.extract(p.q2_7);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_7.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_8;
        }
    }
    state parse_q2_8 {
        pkt.extract(p.q2_8);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_8.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_9;
        }
    }
    state parse_q2_9 {
        pkt.extract(p.q2_9);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_9.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_10;
        }
    }
    state parse_q2_10 {
        pkt.extract(p.q2_10);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_10.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_11;
        }
    }
    state parse_q2_11 {
        pkt.extract(p.q2_11);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_11.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_12;
        }
    }
    state parse_q2_12 {
        pkt.extract(p.q2_12);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_12.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_13;
        }
    }
    state parse_q2_13 {
        pkt.extract(p.q2_13);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_13.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_14;
        }
    }
    state parse_q2_14 {
        pkt.extract(p.q2_14);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_14.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_15;
        }
    }
    state parse_q2_15 {
        pkt.extract(p.q2_15);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_15.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_16;
        }
    }
    state parse_q2_16 {
        pkt.extract(p.q2_16);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_16.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_17;
        }
    }
    state parse_q2_17 {
        pkt.extract(p.q2_17);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_17.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_18;
        }
    }
    state parse_q2_18 {
        pkt.extract(p.q2_18);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_18.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_19;
        }
    }
    state parse_q2_19 {
        pkt.extract(p.q2_19);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_19.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_20;
        }
    }
    state parse_q2_20 {
        pkt.extract(p.q2_20);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_20.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_21;
        }
    }
    state parse_q2_21 {
        pkt.extract(p.q2_21);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_21.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_22;
        }
    }
    state parse_q2_22 {
        pkt.extract(p.q2_22);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_22.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_23;
        }
    }
    state parse_q2_23 {
        pkt.extract(p.q2_23);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_23.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_24;
        }
    }
    state parse_q2_24 {
        pkt.extract(p.q2_24);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_24.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_25;
        }
    }
    state parse_q2_25 {
        pkt.extract(p.q2_25);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_25.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_26;
        }
    }
    state parse_q2_26 {
        pkt.extract(p.q2_26);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_26.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_27;
        }
    }
    state parse_q2_27 {
        pkt.extract(p.q2_27);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_27.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_28;
        }
    }
    state parse_q2_28 {
        pkt.extract(p.q2_28);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_28.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_29;
        }
    }
    state parse_q2_29 {
        pkt.extract(p.q2_29);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_29.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_30;
        }
    }
    state parse_q2_30 {
        pkt.extract(p.q2_30);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_30.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_31;
        }
    }
    state parse_q2_31 {
        pkt.extract(p.q2_31);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_31.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_32;
        }
    }
    state parse_q2_32 {
        pkt.extract(p.q2_32);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_32.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_failure;
        }
    }
    state parse_q2_end {
        transition select(user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: accept;
            false: parse_q3_1;
        }
    }

    state parse_q3_1 {
        pkt.extract(p.q3_1);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_1.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_2;
        }
    }
    state parse_q3_2 {
        pkt.extract(p.q3_2);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_2.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_3;
        }
    }
    state parse_q3_3 {
        pkt.extract(p.q3_3);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_3.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_4;
        }
    }
    state parse_q3_4 {
        pkt.extract(p.q3_4);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_4.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_5;
        }
    }
    state parse_q3_5 {
        pkt.extract(p.q3_5);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_5.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_6;
        }
    }
    state parse_q3_6 {
        pkt.extract(p.q3_6);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_6.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_7;
        }
    }
    state parse_q3_7 {
        pkt.extract(p.q3_7);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_7.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_8;
        }
    }
    state parse_q3_8 {
        pkt.extract(p.q3_8);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_8.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_9;
        }
    }
    state parse_q3_9 {
        pkt.extract(p.q3_9);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_9.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_10;
        }
    }
    state parse_q3_10 {
        pkt.extract(p.q3_10);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_10.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_11;
        }
    }
    state parse_q3_11 {
        pkt.extract(p.q3_11);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_11.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_12;
        }
    }
    state parse_q3_12 {
        pkt.extract(p.q3_12);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_12.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_13;
        }
    }
    state parse_q3_13 {
        pkt.extract(p.q3_13);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_13.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_14;
        }
    }
    state parse_q3_14 {
        pkt.extract(p.q3_14);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_14.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_15;
        }
    }
    state parse_q3_15 {
        pkt.extract(p.q3_15);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_15.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_16;
        }
    }
    state parse_q3_16 {
        pkt.extract(p.q3_16);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_16.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_17;
        }
    }
    state parse_q3_17 {
        pkt.extract(p.q3_17);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_17.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_18;
        }
    }
    state parse_q3_18 {
        pkt.extract(p.q3_18);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_18.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_19;
        }
    }
    state parse_q3_19 {
        pkt.extract(p.q3_19);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_19.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_20;
        }
    }
    state parse_q3_20 {
        pkt.extract(p.q3_20);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_20.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_21;
        }
    }
    state parse_q3_21 {
        pkt.extract(p.q3_21);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_21.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_22;
        }
    }
    state parse_q3_22 {
        pkt.extract(p.q3_22);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_22.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_23;
        }
    }
    state parse_q3_23 {
        pkt.extract(p.q3_23);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_23.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_24;
        }
    }
    state parse_q3_24 {
        pkt.extract(p.q3_24);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_24.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_25;
        }
    }
    state parse_q3_25 {
        pkt.extract(p.q3_25);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_25.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_26;
        }
    }
    state parse_q3_26 {
        pkt.extract(p.q3_26);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_26.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_27;
        }
    }
    state parse_q3_27 {
        pkt.extract(p.q3_27);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_27.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_28;
        }
    }
    state parse_q3_28 {
        pkt.extract(p.q3_28);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_28.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_29;
        }
    }
    state parse_q3_29 {
        pkt.extract(p.q3_29);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_29.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_30;
        }
    }
    state parse_q3_30 {
        pkt.extract(p.q3_30);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_30.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_31;
        }
    }
    state parse_q3_31 {
        pkt.extract(p.q3_31);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_31.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_32;
        }
    }
    state parse_q3_32 {
        pkt.extract(p.q3_32);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_32.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_failure;
        }
    }
    state parse_q3_end {
        transition select(user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: accept;
            false: parse_q4_1;
        }
    }

    state parse_q4_1 {
        pkt.extract(p.q4_1);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_1.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_2;
        }
    }
    state parse_q4_2 {
        pkt.extract(p.q4_2);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_2.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_3;
        }
    }
    state parse_q4_3 {
        pkt.extract(p.q4_3);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_3.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_4;
        }
    }
    state parse_q4_4 {
        pkt.extract(p.q4_4);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_4.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_5;
        }
    }
    state parse_q4_5 {
        pkt.extract(p.q4_5);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_5.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_6;
        }
    }
    state parse_q4_6 {
        pkt.extract(p.q4_6);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_6.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_7;
        }
    }
    state parse_q4_7 {
        pkt.extract(p.q4_7);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_7.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_8;
        }
    }
    state parse_q4_8 {
        pkt.extract(p.q4_8);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_8.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_9;
        }
    }
    state parse_q4_9 {
        pkt.extract(p.q4_9);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_9.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_10;
        }
    }
    state parse_q4_10 {
        pkt.extract(p.q4_10);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_10.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_11;
        }
    }
    state parse_q4_11 {
        pkt.extract(p.q4_11);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_11.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_12;
        }
    }
    state parse_q4_12 {
        pkt.extract(p.q4_12);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_12.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_13;
        }
    }
    state parse_q4_13 {
        pkt.extract(p.q4_13);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_13.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_14;
        }
    }
    state parse_q4_14 {
        pkt.extract(p.q4_14);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_14.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_15;
        }
    }
    state parse_q4_15 {
        pkt.extract(p.q4_15);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_15.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_16;
        }
    }
    state parse_q4_16 {
        pkt.extract(p.q4_16);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_16.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_17;
        }
    }
    state parse_q4_17 {
        pkt.extract(p.q4_17);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_17.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_18;
        }
    }
    state parse_q4_18 {
        pkt.extract(p.q4_18);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_18.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_19;
        }
    }
    state parse_q4_19 {
        pkt.extract(p.q4_19);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_19.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_20;
        }
    }
    state parse_q4_20 {
        pkt.extract(p.q4_20);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_20.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_21;
        }
    }
    state parse_q4_21 {
        pkt.extract(p.q4_21);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_21.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_22;
        }
    }
    state parse_q4_22 {
        pkt.extract(p.q4_22);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_22.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_23;
        }
    }
    state parse_q4_23 {
        pkt.extract(p.q4_23);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_23.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_24;
        }
    }
    state parse_q4_24 {
        pkt.extract(p.q4_24);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_24.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_25;
        }
    }
    state parse_q4_25 {
        pkt.extract(p.q4_25);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_25.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_26;
        }
    }
    state parse_q4_26 {
        pkt.extract(p.q4_26);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_26.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_27;
        }
    }
    state parse_q4_27 {
        pkt.extract(p.q4_27);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_27.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_28;
        }
    }
    state parse_q4_28 {
        pkt.extract(p.q4_28);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_28.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_29;
        }
    }
    state parse_q4_29 {
        pkt.extract(p.q4_29);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_29.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_30;
        }
    }
    state parse_q4_30 {
        pkt.extract(p.q4_30);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_30.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_31;
        }
    }
    state parse_q4_31 {
        pkt.extract(p.q4_31);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_31.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_32;
        }
    }
    state parse_q4_32 {
        pkt.extract(p.q4_32);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_32.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_failure;
        }
    }
    state parse_q4_end {
        transition select(user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: accept;
            false: parse_q5_1;
        }
    }

    state parse_q5_1 {
        pkt.extract(p.q5_1);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_1.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_2;
        }
    }
    state parse_q5_2 {
        pkt.extract(p.q5_2);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_2.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_3;
        }
    }
    state parse_q5_3 {
        pkt.extract(p.q5_3);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_3.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_4;
        }
    }
    state parse_q5_4 {
        pkt.extract(p.q5_4);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_4.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_5;
        }
    }
    state parse_q5_5 {
        pkt.extract(p.q5_5);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_5.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_6;
        }
    }
    state parse_q5_6 {
        pkt.extract(p.q5_6);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_6.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_7;
        }
    }
    state parse_q5_7 {
        pkt.extract(p.q5_7);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_7.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_8;
        }
    }
    state parse_q5_8 {
        pkt.extract(p.q5_8);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_8.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_9;
        }
    }
    state parse_q5_9 {
        pkt.extract(p.q5_9);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_9.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_10;
        }
    }
    state parse_q5_10 {
        pkt.extract(p.q5_10);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_10.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_11;
        }
    }
    state parse_q5_11 {
        pkt.extract(p.q5_11);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_11.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_12;
        }
    }
    state parse_q5_12 {
        pkt.extract(p.q5_12);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_12.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_13;
        }
    }
    state parse_q5_13 {
        pkt.extract(p.q5_13);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_13.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_14;
        }
    }
    state parse_q5_14 {
        pkt.extract(p.q5_14);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_14.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_15;
        }
    }
    state parse_q5_15 {
        pkt.extract(p.q5_15);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_15.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_16;
        }
    }
    state parse_q5_16 {
        pkt.extract(p.q5_16);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_16.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_17;
        }
    }
    state parse_q5_17 {
        pkt.extract(p.q5_17);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_17.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_18;
        }
    }
    state parse_q5_18 {
        pkt.extract(p.q5_18);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_18.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_19;
        }
    }
    state parse_q5_19 {
        pkt.extract(p.q5_19);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_19.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_20;
        }
    }
    state parse_q5_20 {
        pkt.extract(p.q5_20);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_20.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_21;
        }
    }
    state parse_q5_21 {
        pkt.extract(p.q5_21);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_21.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_22;
        }
    }
    state parse_q5_22 {
        pkt.extract(p.q5_22);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_22.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_23;
        }
    }
    state parse_q5_23 {
        pkt.extract(p.q5_23);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_23.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_24;
        }
    }
    state parse_q5_24 {
        pkt.extract(p.q5_24);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_24.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_25;
        }
    }
    state parse_q5_25 {
        pkt.extract(p.q5_25);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_25.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_26;
        }
    }
    state parse_q5_26 {
        pkt.extract(p.q5_26);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_26.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_27;
        }
    }
    state parse_q5_27 {
        pkt.extract(p.q5_27);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_27.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_28;
        }
    }
    state parse_q5_28 {
        pkt.extract(p.q5_28);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_28.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_29;
        }
    }
    state parse_q5_29 {
        pkt.extract(p.q5_29);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_29.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_30;
        }
    }
    state parse_q5_30 {
        pkt.extract(p.q5_30);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_30.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_q5_31;
        }
    }
    state parse_q5_31 {
        pkt.extract(p.q5_31);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q5_31.char == 0x2e || user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: parse_q5_end;
            false: parse_failure;
        }
    }
    state parse_q5_end {
        transition select(user_metadata.domain_chars_parsed >= p.tlsdomainheader.domainlength) {
            true: accept;
            false: parse_failure;
        }
    }

    state parse_failure {
        user_metadata.domain_parsed = 0;
        transition accept;
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

        user_metadata.last_label = 0;

        p.q5_part1.part = 0;
        p.q5_part2.part = 0;
        p.q5_part4.part = 0;
        p.q5_part8_1.part = 0;
        p.q5_part8_2.part = 0;
        p.q5_part16_1.part = 0;
        p.q5_part16_2.part = 0;
        p.q5_part16_3.part = 0;
        p.q5_part16_4.part = 0;

        p.q4_part1.part = 0;
        p.q4_part2.part = 0;
        p.q4_part4.part = 0;
        p.q4_part8_1.part = 0;
        p.q4_part8_2.part = 0;
        p.q4_part16_1.part = 0;
        p.q4_part16_2.part = 0;
        p.q4_part16_3.part = 0;
        p.q4_part16_4.part = 0;

        p.q3_part1.part = 0;
        p.q3_part2.part = 0;
        p.q3_part4.part = 0;
        p.q3_part8_1.part = 0;
        p.q3_part8_2.part = 0;
        p.q3_part16_1.part = 0;
        p.q3_part16_2.part = 0;
        p.q3_part16_3.part = 0;
        p.q3_part16_4.part = 0;

        p.q2_part1.part = 0;
        p.q2_part2.part = 0;
        p.q2_part4.part = 0;
        p.q2_part8_1.part = 0;
        p.q2_part8_2.part = 0;
        p.q2_part16_1.part = 0;
        p.q2_part16_2.part = 0;
        p.q2_part16_3.part = 0;
        p.q2_part16_4.part = 0;

        p.q1_part1.part = 0;
        p.q1_part2.part = 0;
        p.q1_part4.part = 0;
        p.q1_part8_1.part = 0;
        p.q1_part8_2.part = 0;
        p.q1_part16_1.part = 0;
        p.q1_part16_2.part = 0;
        p.q1_part16_3.part = 0;
        p.q1_part16_4.part = 0;

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
            0: parse_query_tc;
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
            16: parse_dns_q1_len16;
            17: parse_dns_q1_len17;
            18: parse_dns_q1_len18;
            19: parse_dns_q1_len19;
            20: parse_dns_q1_len20;
            21: parse_dns_q1_len21;
            22: parse_dns_q1_len22;
            23: parse_dns_q1_len23;
            24: parse_dns_q1_len24;
            25: parse_dns_q1_len25;
            26: parse_dns_q1_len26;
            27: parse_dns_q1_len27;
            28: parse_dns_q1_len28;
            29: parse_dns_q1_len29;
            30: parse_dns_q1_len30;
            31: parse_dns_q1_len31;
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
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len9 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len10 {
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len11 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len12 {
        pkt.extract(p.q1_part4);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len13 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part4);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len14 {
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len15 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len16 {
        pkt.extract(p.q1_part16_1);
        pkt.extract(p.q1_part16_2);
        pkt.extract(p.q1_part16_3);
        pkt.extract(p.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len17 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part16_1);
        pkt.extract(p.q1_part16_2);
        pkt.extract(p.q1_part16_3);
        pkt.extract(p.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len18 {
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part16_1);
        pkt.extract(p.q1_part16_2);
        pkt.extract(p.q1_part16_3);
        pkt.extract(p.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len19 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part16_1);
        pkt.extract(p.q1_part16_2);
        pkt.extract(p.q1_part16_3);
        pkt.extract(p.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len20 {
        pkt.extract(p.q1_part4);
        pkt.extract(p.q1_part16_1);
        pkt.extract(p.q1_part16_2);
        pkt.extract(p.q1_part16_3);
        pkt.extract(p.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len21 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part4);
        pkt.extract(p.q1_part16_1);
        pkt.extract(p.q1_part16_2);
        pkt.extract(p.q1_part16_3);
        pkt.extract(p.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len22 {
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        pkt.extract(p.q1_part16_1);
        pkt.extract(p.q1_part16_2);
        pkt.extract(p.q1_part16_3);
        pkt.extract(p.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len23 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        pkt.extract(p.q1_part16_1);
        pkt.extract(p.q1_part16_2);
        pkt.extract(p.q1_part16_3);
        pkt.extract(p.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len24 {
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        pkt.extract(p.q1_part16_1);
        pkt.extract(p.q1_part16_2);
        pkt.extract(p.q1_part16_3);
        pkt.extract(p.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len25 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        pkt.extract(p.q1_part16_1);
        pkt.extract(p.q1_part16_2);
        pkt.extract(p.q1_part16_3);
        pkt.extract(p.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len26 {
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        pkt.extract(p.q1_part16_1);
        pkt.extract(p.q1_part16_2);
        pkt.extract(p.q1_part16_3);
        pkt.extract(p.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len27 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        pkt.extract(p.q1_part16_1);
        pkt.extract(p.q1_part16_2);
        pkt.extract(p.q1_part16_3);
        pkt.extract(p.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len28 {
        pkt.extract(p.q1_part4);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        pkt.extract(p.q1_part16_1);
        pkt.extract(p.q1_part16_2);
        pkt.extract(p.q1_part16_3);
        pkt.extract(p.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len29 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part4);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        pkt.extract(p.q1_part16_1);
        pkt.extract(p.q1_part16_2);
        pkt.extract(p.q1_part16_3);
        pkt.extract(p.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len30 {
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        pkt.extract(p.q1_part16_1);
        pkt.extract(p.q1_part16_2);
        pkt.extract(p.q1_part16_3);
        pkt.extract(p.q1_part16_4);
        transition parse_dns_query2;
    }

    state parse_dns_q1_len31 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        pkt.extract(p.q1_part8_1);
        pkt.extract(p.q1_part8_2);
        pkt.extract(p.q1_part16_1);
        pkt.extract(p.q1_part16_2);
        pkt.extract(p.q1_part16_3);
        pkt.extract(p.q1_part16_4);
        transition parse_dns_query2;
    }

    // Parsel DNS Query Label 2
    state parse_dns_query2 {
        pkt.extract(p.label2);
        user_metadata.last_label = 2;

        transition select(p.label2.label) {
            0: parse_query_tc;
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
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len9 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len10 {
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len11 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len12 {
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len13 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len14 {
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len15 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len16 {
        pkt.extract(p.q2_part16_1);
        pkt.extract(p.q2_part16_2);
        pkt.extract(p.q2_part16_3);
        pkt.extract(p.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len17 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part16_1);
        pkt.extract(p.q2_part16_2);
        pkt.extract(p.q2_part16_3);
        pkt.extract(p.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len18 {
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part16_1);
        pkt.extract(p.q2_part16_2);
        pkt.extract(p.q2_part16_3);
        pkt.extract(p.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len19 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part16_1);
        pkt.extract(p.q2_part16_2);
        pkt.extract(p.q2_part16_3);
        pkt.extract(p.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len20 {
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part16_1);
        pkt.extract(p.q2_part16_2);
        pkt.extract(p.q2_part16_3);
        pkt.extract(p.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len21 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part16_1);
        pkt.extract(p.q2_part16_2);
        pkt.extract(p.q2_part16_3);
        pkt.extract(p.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len22 {
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part16_1);
        pkt.extract(p.q2_part16_2);
        pkt.extract(p.q2_part16_3);
        pkt.extract(p.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len23 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part16_1);
        pkt.extract(p.q2_part16_2);
        pkt.extract(p.q2_part16_3);
        pkt.extract(p.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len24 {
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        pkt.extract(p.q2_part16_1);
        pkt.extract(p.q2_part16_2);
        pkt.extract(p.q2_part16_3);
        pkt.extract(p.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len25 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        pkt.extract(p.q2_part16_1);
        pkt.extract(p.q2_part16_2);
        pkt.extract(p.q2_part16_3);
        pkt.extract(p.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len26 {
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        pkt.extract(p.q2_part16_1);
        pkt.extract(p.q2_part16_2);
        pkt.extract(p.q2_part16_3);
        pkt.extract(p.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len27 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        pkt.extract(p.q2_part16_1);
        pkt.extract(p.q2_part16_2);
        pkt.extract(p.q2_part16_3);
        pkt.extract(p.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len28 {
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        pkt.extract(p.q2_part16_1);
        pkt.extract(p.q2_part16_2);
        pkt.extract(p.q2_part16_3);
        pkt.extract(p.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len29 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        pkt.extract(p.q2_part16_1);
        pkt.extract(p.q2_part16_2);
        pkt.extract(p.q2_part16_3);
        pkt.extract(p.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len30 {
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        pkt.extract(p.q2_part16_1);
        pkt.extract(p.q2_part16_2);
        pkt.extract(p.q2_part16_3);
        pkt.extract(p.q2_part16_4);
        transition parse_dns_query3;
    }

    state parse_dns_q2_len31 {
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part4);
        pkt.extract(p.q2_part8_1);
        pkt.extract(p.q2_part8_2);
        pkt.extract(p.q2_part16_1);
        pkt.extract(p.q2_part16_2);
        pkt.extract(p.q2_part16_3);
        pkt.extract(p.q2_part16_4);
        transition parse_dns_query3;
    }

    
    // Parsel DNS Query Label 3
    state parse_dns_query3 {
        pkt.extract(p.label3);
        user_metadata.last_label = 3;

        transition select(p.label3.label) {
            0: parse_query_tc;
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
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len9 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len10 {
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len11 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len12 {
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len13 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len14 {
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len15 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len16 {
        pkt.extract(p.q3_part16_1);
        pkt.extract(p.q3_part16_2);
        pkt.extract(p.q3_part16_3);
        pkt.extract(p.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len17 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part16_1);
        pkt.extract(p.q3_part16_2);
        pkt.extract(p.q3_part16_3);
        pkt.extract(p.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len18 {
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part16_1);
        pkt.extract(p.q3_part16_2);
        pkt.extract(p.q3_part16_3);
        pkt.extract(p.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len19 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part16_1);
        pkt.extract(p.q3_part16_2);
        pkt.extract(p.q3_part16_3);
        pkt.extract(p.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len20 {
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part16_1);
        pkt.extract(p.q3_part16_2);
        pkt.extract(p.q3_part16_3);
        pkt.extract(p.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len21 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part16_1);
        pkt.extract(p.q3_part16_2);
        pkt.extract(p.q3_part16_3);
        pkt.extract(p.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len22 {
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part16_1);
        pkt.extract(p.q3_part16_2);
        pkt.extract(p.q3_part16_3);
        pkt.extract(p.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len23 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part16_1);
        pkt.extract(p.q3_part16_2);
        pkt.extract(p.q3_part16_3);
        pkt.extract(p.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len24 {
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        pkt.extract(p.q3_part16_1);
        pkt.extract(p.q3_part16_2);
        pkt.extract(p.q3_part16_3);
        pkt.extract(p.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len25 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        pkt.extract(p.q3_part16_1);
        pkt.extract(p.q3_part16_2);
        pkt.extract(p.q3_part16_3);
        pkt.extract(p.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len26 {
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        pkt.extract(p.q3_part16_1);
        pkt.extract(p.q3_part16_2);
        pkt.extract(p.q3_part16_3);
        pkt.extract(p.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len27 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        pkt.extract(p.q3_part16_1);
        pkt.extract(p.q3_part16_2);
        pkt.extract(p.q3_part16_3);
        pkt.extract(p.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len28 {
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        pkt.extract(p.q3_part16_1);
        pkt.extract(p.q3_part16_2);
        pkt.extract(p.q3_part16_3);
        pkt.extract(p.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len29 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        pkt.extract(p.q3_part16_1);
        pkt.extract(p.q3_part16_2);
        pkt.extract(p.q3_part16_3);
        pkt.extract(p.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len30 {
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        pkt.extract(p.q3_part16_1);
        pkt.extract(p.q3_part16_2);
        pkt.extract(p.q3_part16_3);
        pkt.extract(p.q3_part16_4);
        transition parse_dns_query4;
    }

    state parse_dns_q3_len31 {
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part4);
        pkt.extract(p.q3_part8_1);
        pkt.extract(p.q3_part8_2);
        pkt.extract(p.q3_part16_1);
        pkt.extract(p.q3_part16_2);
        pkt.extract(p.q3_part16_3);
        pkt.extract(p.q3_part16_4);
        transition parse_dns_query4;
    }

    
    // Parsel DNS Query Label 4
    state parse_dns_query4 {
        pkt.extract(p.label4);
        user_metadata.last_label = 4;

        transition select(p.label4.label) {
            0: parse_query_tc;
            1: parse_dns_q4_len1;
            2: parse_dns_q4_len2;
            3: parse_dns_q4_len3;
            4: parse_dns_q4_len4;
            5: parse_dns_q4_len5;
            6: parse_dns_q4_len6;
            7: parse_dns_q4_len7;
            8: parse_dns_q4_len8;
            9: parse_dns_q4_len9;
            10: parse_dns_q4_len10;
            11: parse_dns_q4_len11;
            12: parse_dns_q4_len12;
            13: parse_dns_q4_len13;
            14: parse_dns_q4_len14;
            15: parse_dns_q4_len15;
            16: parse_dns_q4_len16;
            17: parse_dns_q4_len17;
            18: parse_dns_q4_len18;
            19: parse_dns_q4_len19;
            20: parse_dns_q4_len20;
            21: parse_dns_q4_len21;
            22: parse_dns_q4_len22;
            23: parse_dns_q4_len23;
            24: parse_dns_q4_len24;
            25: parse_dns_q4_len25;
            26: parse_dns_q4_len26;
            27: parse_dns_q4_len27;
            28: parse_dns_q4_len28;
            29: parse_dns_q4_len29;
            30: parse_dns_q4_len30;
            31: parse_dns_q4_len31;
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

    state parse_dns_q4_len8 {
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len9 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len10 {
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len11 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len12 {
        pkt.extract(p.q4_part4);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len13 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part4);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len14 {
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part4);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len15 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part4);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len16 {
        pkt.extract(p.q4_part16_1);
        pkt.extract(p.q4_part16_2);
        pkt.extract(p.q4_part16_3);
        pkt.extract(p.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len17 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part16_1);
        pkt.extract(p.q4_part16_2);
        pkt.extract(p.q4_part16_3);
        pkt.extract(p.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len18 {
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part16_1);
        pkt.extract(p.q4_part16_2);
        pkt.extract(p.q4_part16_3);
        pkt.extract(p.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len19 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part16_1);
        pkt.extract(p.q4_part16_2);
        pkt.extract(p.q4_part16_3);
        pkt.extract(p.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len20 {
        pkt.extract(p.q4_part4);
        pkt.extract(p.q4_part16_1);
        pkt.extract(p.q4_part16_2);
        pkt.extract(p.q4_part16_3);
        pkt.extract(p.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len21 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part4);
        pkt.extract(p.q4_part16_1);
        pkt.extract(p.q4_part16_2);
        pkt.extract(p.q4_part16_3);
        pkt.extract(p.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len22 {
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part4);
        pkt.extract(p.q4_part16_1);
        pkt.extract(p.q4_part16_2);
        pkt.extract(p.q4_part16_3);
        pkt.extract(p.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len23 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part4);
        pkt.extract(p.q4_part16_1);
        pkt.extract(p.q4_part16_2);
        pkt.extract(p.q4_part16_3);
        pkt.extract(p.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len24 {
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        pkt.extract(p.q4_part16_1);
        pkt.extract(p.q4_part16_2);
        pkt.extract(p.q4_part16_3);
        pkt.extract(p.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len25 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        pkt.extract(p.q4_part16_1);
        pkt.extract(p.q4_part16_2);
        pkt.extract(p.q4_part16_3);
        pkt.extract(p.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len26 {
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        pkt.extract(p.q4_part16_1);
        pkt.extract(p.q4_part16_2);
        pkt.extract(p.q4_part16_3);
        pkt.extract(p.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len27 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        pkt.extract(p.q4_part16_1);
        pkt.extract(p.q4_part16_2);
        pkt.extract(p.q4_part16_3);
        pkt.extract(p.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len28 {
        pkt.extract(p.q4_part4);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        pkt.extract(p.q4_part16_1);
        pkt.extract(p.q4_part16_2);
        pkt.extract(p.q4_part16_3);
        pkt.extract(p.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len29 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part4);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        pkt.extract(p.q4_part16_1);
        pkt.extract(p.q4_part16_2);
        pkt.extract(p.q4_part16_3);
        pkt.extract(p.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len30 {
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part4);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        pkt.extract(p.q4_part16_1);
        pkt.extract(p.q4_part16_2);
        pkt.extract(p.q4_part16_3);
        pkt.extract(p.q4_part16_4);
        transition parse_dns_query5;
    }

    state parse_dns_q4_len31 {
        pkt.extract(p.q4_part1);
        pkt.extract(p.q4_part2);
        pkt.extract(p.q4_part4);
        pkt.extract(p.q4_part8_1);
        pkt.extract(p.q4_part8_2);
        pkt.extract(p.q4_part16_1);
        pkt.extract(p.q4_part16_2);
        pkt.extract(p.q4_part16_3);
        pkt.extract(p.q4_part16_4);
        transition parse_dns_query5;
    }

    // Parsel DNS Query Label 5
    state parse_dns_query5 {
        pkt.extract(p.label5);
        user_metadata.last_label = 5;

        transition select(p.label5.label) {
            0: parse_query_tc;
            1: parse_dns_q5_len1;
            2: parse_dns_q5_len2;
            3: parse_dns_q5_len3;
            4: parse_dns_q5_len4;
            5: parse_dns_q5_len5;
            6: parse_dns_q5_len6;
            7: parse_dns_q5_len7;
            8: parse_dns_q5_len8;
            9: parse_dns_q5_len9;
            10: parse_dns_q5_len10;
            11: parse_dns_q5_len11;
            12: parse_dns_q5_len12;
            13: parse_dns_q5_len13;
            14: parse_dns_q5_len14;
            15: parse_dns_q5_len15;
            16: parse_dns_q5_len16;
            17: parse_dns_q5_len17;
            18: parse_dns_q5_len18;
            19: parse_dns_q5_len19;
            20: parse_dns_q5_len20;
            21: parse_dns_q5_len21;
            22: parse_dns_q5_len22;
            23: parse_dns_q5_len23;
            24: parse_dns_q5_len24;
            25: parse_dns_q5_len25;
            26: parse_dns_q5_len26;
            27: parse_dns_q5_len27;
            28: parse_dns_q5_len28;
            29: parse_dns_q5_len29;
            30: parse_dns_q5_len30;
            31: parse_dns_q5_len31;
            default: accept;
        }
    }

    state parse_dns_q5_len1 {
        pkt.extract(p.q5_part1);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len2 {
        pkt.extract(p.q5_part2);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len3 {
        pkt.extract(p.q5_part1);
        pkt.extract(p.q5_part2);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len4 {
        pkt.extract(p.q5_part4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len5 {
        pkt.extract(p.q5_part1);
        pkt.extract(p.q5_part4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len6 {
        pkt.extract(p.q5_part2);
        pkt.extract(p.q5_part4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len7 {
        pkt.extract(p.q5_part1);
        pkt.extract(p.q5_part2);
        pkt.extract(p.q5_part4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len8 {
        pkt.extract(p.q5_part8_1);
        pkt.extract(p.q5_part8_2);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len9 {
        pkt.extract(p.q5_part1);
        pkt.extract(p.q5_part8_1);
        pkt.extract(p.q5_part8_2);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len10 {
        pkt.extract(p.q5_part2);
        pkt.extract(p.q5_part8_1);
        pkt.extract(p.q5_part8_2);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len11 {
        pkt.extract(p.q5_part1);
        pkt.extract(p.q5_part2);
        pkt.extract(p.q5_part8_1);
        pkt.extract(p.q5_part8_2);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len12 {
        pkt.extract(p.q5_part4);
        pkt.extract(p.q5_part8_1);
        pkt.extract(p.q5_part8_2);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len13 {
        pkt.extract(p.q5_part1);
        pkt.extract(p.q5_part4);
        pkt.extract(p.q5_part8_1);
        pkt.extract(p.q5_part8_2);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len14 {
        pkt.extract(p.q5_part2);
        pkt.extract(p.q5_part4);
        pkt.extract(p.q5_part8_1);
        pkt.extract(p.q5_part8_2);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len15 {
        pkt.extract(p.q5_part1);
        pkt.extract(p.q5_part2);
        pkt.extract(p.q5_part4);
        pkt.extract(p.q5_part8_1);
        pkt.extract(p.q5_part8_2);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len16 {
        pkt.extract(p.q5_part16_1);
        pkt.extract(p.q5_part16_2);
        pkt.extract(p.q5_part16_3);
        pkt.extract(p.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len17 {
        pkt.extract(p.q5_part1);
        pkt.extract(p.q5_part16_1);
        pkt.extract(p.q5_part16_2);
        pkt.extract(p.q5_part16_3);
        pkt.extract(p.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len18 {
        pkt.extract(p.q5_part2);
        pkt.extract(p.q5_part16_1);
        pkt.extract(p.q5_part16_2);
        pkt.extract(p.q5_part16_3);
        pkt.extract(p.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len19 {
        pkt.extract(p.q5_part1);
        pkt.extract(p.q5_part2);
        pkt.extract(p.q5_part16_1);
        pkt.extract(p.q5_part16_2);
        pkt.extract(p.q5_part16_3);
        pkt.extract(p.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len20 {
        pkt.extract(p.q5_part4);
        pkt.extract(p.q5_part16_1);
        pkt.extract(p.q5_part16_2);
        pkt.extract(p.q5_part16_3);
        pkt.extract(p.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len21 {
        pkt.extract(p.q5_part1);
        pkt.extract(p.q5_part4);
        pkt.extract(p.q5_part16_1);
        pkt.extract(p.q5_part16_2);
        pkt.extract(p.q5_part16_3);
        pkt.extract(p.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len22 {
        pkt.extract(p.q5_part2);
        pkt.extract(p.q5_part4);
        pkt.extract(p.q5_part16_1);
        pkt.extract(p.q5_part16_2);
        pkt.extract(p.q5_part16_3);
        pkt.extract(p.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len23 {
        pkt.extract(p.q5_part1);
        pkt.extract(p.q5_part2);
        pkt.extract(p.q5_part4);
        pkt.extract(p.q5_part16_1);
        pkt.extract(p.q5_part16_2);
        pkt.extract(p.q5_part16_3);
        pkt.extract(p.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len24 {
        pkt.extract(p.q5_part8_1);
        pkt.extract(p.q5_part8_2);
        pkt.extract(p.q5_part16_1);
        pkt.extract(p.q5_part16_2);
        pkt.extract(p.q5_part16_3);
        pkt.extract(p.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len25 {
        pkt.extract(p.q5_part1);
        pkt.extract(p.q5_part8_1);
        pkt.extract(p.q5_part8_2);
        pkt.extract(p.q5_part16_1);
        pkt.extract(p.q5_part16_2);
        pkt.extract(p.q5_part16_3);
        pkt.extract(p.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len26 {
        pkt.extract(p.q5_part2);
        pkt.extract(p.q5_part8_1);
        pkt.extract(p.q5_part8_2);
        pkt.extract(p.q5_part16_1);
        pkt.extract(p.q5_part16_2);
        pkt.extract(p.q5_part16_3);
        pkt.extract(p.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len27 {
        pkt.extract(p.q5_part1);
        pkt.extract(p.q5_part2);
        pkt.extract(p.q5_part8_1);
        pkt.extract(p.q5_part8_2);
        pkt.extract(p.q5_part16_1);
        pkt.extract(p.q5_part16_2);
        pkt.extract(p.q5_part16_3);
        pkt.extract(p.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len28 {
        pkt.extract(p.q5_part4);
        pkt.extract(p.q5_part8_1);
        pkt.extract(p.q5_part8_2);
        pkt.extract(p.q5_part16_1);
        pkt.extract(p.q5_part16_2);
        pkt.extract(p.q5_part16_3);
        pkt.extract(p.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len29 {
        pkt.extract(p.q5_part1);
        pkt.extract(p.q5_part4);
        pkt.extract(p.q5_part8_1);
        pkt.extract(p.q5_part8_2);
        pkt.extract(p.q5_part16_1);
        pkt.extract(p.q5_part16_2);
        pkt.extract(p.q5_part16_3);
        pkt.extract(p.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len30 {
        pkt.extract(p.q5_part2);
        pkt.extract(p.q5_part4);
        pkt.extract(p.q5_part8_1);
        pkt.extract(p.q5_part8_2);
        pkt.extract(p.q5_part16_1);
        pkt.extract(p.q5_part16_2);
        pkt.extract(p.q5_part16_3);
        pkt.extract(p.q5_part16_4);
        transition parse_dns_query6;
    }

    state parse_dns_q5_len31 {
        pkt.extract(p.q5_part1);
        pkt.extract(p.q5_part2);
        pkt.extract(p.q5_part4);
        pkt.extract(p.q5_part8_1);
        pkt.extract(p.q5_part8_2);
        pkt.extract(p.q5_part16_1);
        pkt.extract(p.q5_part16_2);
        pkt.extract(p.q5_part16_3);
        pkt.extract(p.q5_part16_4);
        transition parse_dns_query6;
    }


    // Parsel DNS Query Label 6
    state parse_dns_query6 {
        pkt.extract(p.label6);
        user_metadata.last_label = 6;

        transition select(p.label6.label) {
            0: parse_query_tc;
            default: accept;
        }
    }

    state parse_query_tc {
        pkt.extract(p.query_tc);
        user_metadata.parsed_answer = 0;
        transition parse_dns_answer;
    }

    state parse_dns_answer {
        pkt.extract(p.dns_answer);

        transition select(p.dns_answer.tc_ans.type) {
            1: parse_a_ip;
            5: parse_cname;
            default: accept;
        }
    }

    state parse_cname {
        pkt.advance(8 * (bit<32>)(p.dns_answer.rd_length));

        transition parse_dns_answer;
    }

    state parse_a_ip {
        pkt.extract(p.dns_ip);
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
    register<bit<32>>(TABLE_SIZE) cip_table_1;
    register<bit<32>>(TABLE_SIZE) sip_table_1;
    register<bit<32>>(TABLE_SIZE) name_table_1;
    register<bit<32>>(TABLE_SIZE) timestamp_table_1;

    register<bit<32>>(TABLE_SIZE) cip_table_2;
    register<bit<32>>(TABLE_SIZE) sip_table_2;
    register<bit<32>>(TABLE_SIZE) name_table_2;
    register<bit<32>>(TABLE_SIZE) timestamp_table_2;

    register<bit<32>>(TABLE_SIZE) cip_table_3;
    register<bit<32>>(TABLE_SIZE) sip_table_3;
    register<bit<32>>(TABLE_SIZE) name_table_3;
    register<bit<32>>(TABLE_SIZE) timestamp_table_3;

    register<bit<32>>(TABLE_SIZE) cip_table_4;
    register<bit<32>>(TABLE_SIZE) sip_table_4;
    register<bit<32>>(TABLE_SIZE) name_table_4;
    register<bit<32>>(TABLE_SIZE) timestamp_table_4;

    // REGISTER ARRAY FOR COLLECTING COUNTS ON TRAFFIC WITH KNOWN DOMAINS
    register<bit<32>>(NUM_KNOWN_DOMAINS) packet_counts_table;
    register<bit<32>>(NUM_KNOWN_DOMAINS) byte_counts_table;

    // REGISTER ARRAY FOR KEEPING TRACK OF OVERFLOW DNS RESPONSES OR TLS CLIEN THELLOS
    register<bit<32>>(NUM_KNOWN_DOMAINS) dns_total_queried;
    register<bit<32>>(NUM_KNOWN_DOMAINS) dns_total_missed;
    register<bit<32>>(NUM_KNOWN_DOMAINS) tls_total_queried;
    register<bit<32>>(NUM_KNOWN_DOMAINS) tls_total_missed;

    action match_q1(known_domain_id q1id) {
        user_metadata.q1_id = q1id;
    }

    action match_q2(known_domain_id q2id) {
        user_metadata.q2_id = q2id;
    }

    action match_q3(known_domain_id q3id) {
        user_metadata.q3_id = q3id;
    }

    action match_q4(known_domain_id q4id) {
        user_metadata.q4_id = q4id;
    }

    action match_q5(known_domain_id q5id) {
        user_metadata.q5_id = q5id;
    }

    action match_domain(known_domain_id id) {
        user_metadata.domain_id = id;
        user_metadata.matched_domain = 1;
    }

    table dnsknown_domain_list_q1 {
        key = {
            headers.q1_part1.part: ternary;
            headers.q1_part2.part: ternary;
            headers.q1_part4.part: ternary;
            headers.q1_part8_1.part: ternary;
            headers.q1_part8_2.part: ternary;
            headers.q1_part16_1.part: ternary;
            headers.q1_part16_2.part: ternary;
            headers.q1_part16_3.part: ternary;
            headers.q1_part16_4.part: ternary;
        }

        actions = {
            match_q1;
            NoAction;
        }
        size = NUM_KNOWN_DOMAINS;
        default_action = NoAction();
    }

    table dnsknown_domain_list_q2 {
        key = {
            headers.q2_part1.part: ternary;
            headers.q2_part2.part: ternary;
            headers.q2_part4.part: ternary;
            headers.q2_part8_1.part: ternary;
            headers.q2_part8_2.part: ternary;
            headers.q2_part16_1.part: ternary;
            headers.q2_part16_2.part: ternary;
            headers.q2_part16_3.part: ternary;
            headers.q2_part16_4.part: ternary;
        }

        actions = {
            match_q2;
            NoAction;
        }
        size = NUM_KNOWN_DOMAINS;
        default_action = NoAction();
    }

    table dnsknown_domain_list_q3 {
        key = {
            headers.q3_part1.part: ternary;
            headers.q3_part2.part: ternary;
            headers.q3_part4.part: ternary;
            headers.q3_part8_1.part: ternary;
            headers.q3_part8_2.part: ternary;
            headers.q3_part16_1.part: ternary;
            headers.q3_part16_2.part: ternary;
            headers.q3_part16_3.part: ternary;
            headers.q3_part16_4.part: ternary;
        }

        actions = {
            match_q3;
            NoAction;
        }
        size = NUM_KNOWN_DOMAINS;
        default_action = NoAction();
    }

    table dnsknown_domain_list_q4 {
        key = {
            headers.q4_part1.part: ternary;
            headers.q4_part2.part: ternary;
            headers.q4_part4.part: ternary;
            headers.q4_part8_1.part: ternary;
            headers.q4_part8_2.part: ternary;
            headers.q4_part16_1.part: ternary;
            headers.q4_part16_2.part: ternary;
            headers.q4_part16_3.part: ternary;
            headers.q4_part16_4.part: ternary;
        }

        actions = {
            match_q4;
            NoAction;
        }
        size = NUM_KNOWN_DOMAINS;
        default_action = NoAction();
    }

    table dnsknown_domain_list_q5 {
        key = {
            headers.q5_part1.part: ternary;
            headers.q5_part2.part: ternary;
            headers.q5_part4.part: ternary;
            headers.q5_part8_1.part: ternary;
            headers.q5_part8_2.part: ternary;
            headers.q5_part16_1.part: ternary;
            headers.q5_part16_2.part: ternary;
            headers.q5_part16_3.part: ternary;
            headers.q5_part16_4.part: ternary;
        }

        actions = {
            match_q5;
            NoAction;
        }
        size = NUM_KNOWN_DOMAINS;
        default_action = NoAction();
    }

    table dnsmatch_known_domain_list {
        key = {
            user_metadata.q1_id: exact;
            user_metadata.q2_id: exact;
            user_metadata.q3_id: exact;
            user_metadata.q4_id: exact;
            user_metadata.q5_id: exact;
        }

        actions = {
            match_domain;
            NoAction;
        }
        size = NUM_KNOWN_DOMAINS;
        default_action = NoAction();
    }

    table tlsknown_domain_list_q1 {
        key = {
            headers.q1_1.char: ternary;
            headers.q1_2.char: ternary;
            headers.q1_3.char: ternary;
            headers.q1_4.char: ternary;
            headers.q1_5.char: ternary;
            headers.q1_6.char: ternary;
            headers.q1_7.char: ternary;
            headers.q1_8.char: ternary;
            headers.q1_9.char: ternary;
            headers.q1_10.char: ternary;
            headers.q1_11.char: ternary;
            headers.q1_12.char: ternary;
            headers.q1_13.char: ternary;
            headers.q1_14.char: ternary;
            headers.q1_15.char: ternary;
            headers.q1_16.char: ternary;
            headers.q1_17.char: ternary;
            headers.q1_18.char: ternary;
            headers.q1_19.char: ternary;
            headers.q1_20.char: ternary;
            headers.q1_21.char: ternary;
            headers.q1_22.char: ternary;
            headers.q1_23.char: ternary;
            headers.q1_24.char: ternary;
            headers.q1_25.char: ternary;
            headers.q1_26.char: ternary;
            headers.q1_27.char: ternary;
            headers.q1_28.char: ternary;
            headers.q1_29.char: ternary;
            headers.q1_30.char: ternary;
            headers.q1_31.char: ternary;
            headers.q1_32.char: ternary;
        }

        actions = {
            match_q1;
            NoAction;
        }
        size = NUM_KNOWN_DOMAINS;
        default_action = NoAction();
    }

    table tlsknown_domain_list_q2 {
        key = {
            headers.q2_1.char: ternary;
            headers.q2_2.char: ternary;
            headers.q2_3.char: ternary;
            headers.q2_4.char: ternary;
            headers.q2_5.char: ternary;
            headers.q2_6.char: ternary;
            headers.q2_7.char: ternary;
            headers.q2_8.char: ternary;
            headers.q2_9.char: ternary;
            headers.q2_10.char: ternary;
            headers.q2_11.char: ternary;
            headers.q2_12.char: ternary;
            headers.q2_13.char: ternary;
            headers.q2_14.char: ternary;
            headers.q2_15.char: ternary;
            headers.q2_16.char: ternary;
            headers.q2_17.char: ternary;
            headers.q2_18.char: ternary;
            headers.q2_19.char: ternary;
            headers.q2_20.char: ternary;
            headers.q2_21.char: ternary;
            headers.q2_22.char: ternary;
            headers.q2_23.char: ternary;
            headers.q2_24.char: ternary;
            headers.q2_25.char: ternary;
            headers.q2_26.char: ternary;
            headers.q2_27.char: ternary;
            headers.q2_28.char: ternary;
            headers.q2_29.char: ternary;
            headers.q2_30.char: ternary;
            headers.q2_31.char: ternary;
            headers.q2_32.char: ternary;
        }

        actions = {
            match_q2;
            NoAction;
        }
        size = NUM_KNOWN_DOMAINS;
        default_action = NoAction();
    }

    table tlsknown_domain_list_q3 {
        key = {
            headers.q3_1.char: ternary;
            headers.q3_2.char: ternary;
            headers.q3_3.char: ternary;
            headers.q3_4.char: ternary;
            headers.q3_5.char: ternary;
            headers.q3_6.char: ternary;
            headers.q3_7.char: ternary;
            headers.q3_8.char: ternary;
            headers.q3_9.char: ternary;
            headers.q3_10.char: ternary;
            headers.q3_11.char: ternary;
            headers.q3_12.char: ternary;
            headers.q3_13.char: ternary;
            headers.q3_14.char: ternary;
            headers.q3_15.char: ternary;
            headers.q3_16.char: ternary;
            headers.q3_17.char: ternary;
            headers.q3_18.char: ternary;
            headers.q3_19.char: ternary;
            headers.q3_20.char: ternary;
            headers.q3_21.char: ternary;
            headers.q3_22.char: ternary;
            headers.q3_23.char: ternary;
            headers.q3_24.char: ternary;
            headers.q3_25.char: ternary;
            headers.q3_26.char: ternary;
            headers.q3_27.char: ternary;
            headers.q3_28.char: ternary;
            headers.q3_29.char: ternary;
            headers.q3_30.char: ternary;
            headers.q3_31.char: ternary;
            headers.q3_32.char: ternary;
        }

        actions = {
            match_q3;
            NoAction;
        }
        size = NUM_KNOWN_DOMAINS;
        default_action = NoAction();
    }

    table tlsknown_domain_list_q4 {
        key = {
            headers.q4_1.char: ternary;
            headers.q4_2.char: ternary;
            headers.q4_3.char: ternary;
            headers.q4_4.char: ternary;
            headers.q4_5.char: ternary;
            headers.q4_6.char: ternary;
            headers.q4_7.char: ternary;
            headers.q4_8.char: ternary;
            headers.q4_9.char: ternary;
            headers.q4_10.char: ternary;
            headers.q4_11.char: ternary;
            headers.q4_12.char: ternary;
            headers.q4_13.char: ternary;
            headers.q4_14.char: ternary;
            headers.q4_15.char: ternary;
            headers.q4_16.char: ternary;
            headers.q4_17.char: ternary;
            headers.q4_18.char: ternary;
            headers.q4_19.char: ternary;
            headers.q4_20.char: ternary;
            headers.q4_21.char: ternary;
            headers.q4_22.char: ternary;
            headers.q4_23.char: ternary;
            headers.q4_24.char: ternary;
            headers.q4_25.char: ternary;
            headers.q4_26.char: ternary;
            headers.q4_27.char: ternary;
            headers.q4_28.char: ternary;
            headers.q4_29.char: ternary;
            headers.q4_30.char: ternary;
            headers.q4_31.char: ternary;
            headers.q4_32.char: ternary;
        }

        actions = {
            match_q4;
            NoAction;
        }
        size = NUM_KNOWN_DOMAINS;
        default_action = NoAction();
    }

    table tlsknown_domain_list_q5 {
        key = {
            headers.q5_1.char: ternary;
            headers.q5_2.char: ternary;
            headers.q5_3.char: ternary;
            headers.q5_4.char: ternary;
            headers.q5_5.char: ternary;
            headers.q5_6.char: ternary;
            headers.q5_7.char: ternary;
            headers.q5_8.char: ternary;
            headers.q5_9.char: ternary;
            headers.q5_10.char: ternary;
            headers.q5_11.char: ternary;
            headers.q5_12.char: ternary;
            headers.q5_13.char: ternary;
            headers.q5_14.char: ternary;
            headers.q5_15.char: ternary;
            headers.q5_16.char: ternary;
            headers.q5_17.char: ternary;
            headers.q5_18.char: ternary;
            headers.q5_19.char: ternary;
            headers.q5_20.char: ternary;
            headers.q5_21.char: ternary;
            headers.q5_22.char: ternary;
            headers.q5_23.char: ternary;
            headers.q5_24.char: ternary;
            headers.q5_25.char: ternary;
            headers.q5_26.char: ternary;
            headers.q5_27.char: ternary;
            headers.q5_28.char: ternary;
            headers.q5_29.char: ternary;
            headers.q5_30.char: ternary;
            headers.q5_31.char: ternary;
        }

        actions = {
            match_q5;
            NoAction;
        }
        size = NUM_KNOWN_DOMAINS;
        default_action = NoAction();
    }

    table tlsmatch_known_domain_list {
        key = {
            user_metadata.q1_id: exact;
            user_metadata.q2_id: exact;
            user_metadata.q3_id: exact;
            user_metadata.q4_id: exact;
            user_metadata.q5_id: exact;
        }

        actions = {
            match_domain;
            NoAction;
        }
        size = NUM_KNOWN_DOMAINS;
        default_action = NoAction();
    }

    action match_banned_dns_dst() {
        user_metadata.matched_domain = 0;
    }

    table allowable_dns_dst {
        key = {
            headers.ipv4.dst: lpm;
        }

        actions = {
            match_banned_dns_dst;
            NoAction;
        }
        size = NUM_ALLOWABLE_DST_IP;
        default_action = match_banned_dns_dst();
    }

    table banned_dns_dst {
        key = {
            headers.ipv4.dst: lpm;
        }

        actions = {
            match_banned_dns_dst;
            NoAction;
        }
        size = NUM_BANNED_DST_IP;
        default_action = NoAction();
    }

    apply {
        if(user_metadata.parsed_answer == 1) {
            user_metadata.q1_id = 0;
            user_metadata.q2_id = 0;
            user_metadata.q3_id = 0;
            user_metadata.q4_id = 0;
            user_metadata.q5_id = 0;
            user_metadata.domain_id = 0;
            user_metadata.matched_domain = 0;

            dnsknown_domain_list_q1.apply();
            dnsknown_domain_list_q2.apply();
            dnsknown_domain_list_q3.apply();
            dnsknown_domain_list_q4.apply();
            dnsknown_domain_list_q5.apply();
            dnsmatch_known_domain_list.apply();

            allowable_dns_dst.apply();
            banned_dns_dst.apply();

            if (user_metadata.matched_domain == 1) {

                // Increment total DNS queries for this domain name
                dns_total_queried.read(user_metadata.temp_total_dns, user_metadata.domain_id);
                dns_total_queried.write(user_metadata.domain_id, user_metadata.temp_total_dns + 1);

                if (headers.dns_ip.rdata > headers.ipv4.dst) {
                    hash(user_metadata.index_1, HashAlgorithm.crc16, HASH_TABLE_BASE, {headers.dns_ip.rdata, 7w11, headers.ipv4.dst}, HASH_TABLE_MAX);
                    hash(user_metadata.index_2, HashAlgorithm.crc16, HASH_TABLE_BASE, {3w5, headers.dns_ip.rdata, 5w3, headers.ipv4.dst}, HASH_TABLE_MAX);
                    hash(user_metadata.index_3, HashAlgorithm.crc16, HASH_TABLE_BASE, {2w0, headers.dns_ip.rdata, 1w1, headers.ipv4.dst}, HASH_TABLE_MAX);
                    hash(user_metadata.index_4, HashAlgorithm.crc16, HASH_TABLE_BASE, {3w7, headers.dns_ip.rdata, 5w12, headers.ipv4.dst}, HASH_TABLE_MAX);
                }
                else {
                    hash(user_metadata.index_1, HashAlgorithm.crc16, HASH_TABLE_BASE, {headers.ipv4.dst, 7w11, headers.dns_ip.rdata}, HASH_TABLE_MAX);
                    hash(user_metadata.index_2, HashAlgorithm.crc16, HASH_TABLE_BASE, {3w5, headers.ipv4.dst, 5w3, headers.dns_ip.rdata}, HASH_TABLE_MAX);
                    hash(user_metadata.index_3, HashAlgorithm.crc16, HASH_TABLE_BASE, {2w0, headers.ipv4.dst, 1w1, headers.dns_ip.rdata}, HASH_TABLE_MAX);
                    hash(user_metadata.index_4, HashAlgorithm.crc16, HASH_TABLE_BASE, {3w7, headers.ipv4.dst, 5w12, headers.dns_ip.rdata}, HASH_TABLE_MAX);
                }

                user_metadata.already_matched = 0;
                // access table 1
                cip_table_1.read(user_metadata.temp_cip, user_metadata.index_1);
                sip_table_1.read(user_metadata.temp_sip, user_metadata.index_1);
                timestamp_table_1.read(user_metadata.temp_timestamp, user_metadata.index_1);
                if (user_metadata.temp_timestamp == 0 || user_metadata.temp_timestamp + TIMEOUT < (bit<32>)standard_metadata.ingress_global_timestamp || (user_metadata.temp_cip == headers.ipv4.dst && user_metadata.temp_sip == headers.dns_ip.rdata)) {
                    cip_table_1.write(user_metadata.index_1, headers.ipv4.dst);
                    sip_table_1.write(user_metadata.index_1, headers.dns_ip.rdata);
                    timestamp_table_1.write(user_metadata.index_1, (bit<32>)standard_metadata.ingress_global_timestamp);
                    name_table_1.write(user_metadata.index_1, user_metadata.domain_id);
                    user_metadata.already_matched = 1;
                }

                // access table 2
                if (user_metadata.already_matched == 0) {
                    cip_table_2.read(user_metadata.temp_cip, user_metadata.index_2);
                    sip_table_2.read(user_metadata.temp_sip, user_metadata.index_2);
                    timestamp_table_2.read(user_metadata.temp_timestamp, user_metadata.index_2);
                    if (user_metadata.temp_timestamp == 0 || user_metadata.temp_timestamp + TIMEOUT < (bit<32>)standard_metadata.ingress_global_timestamp || (user_metadata.temp_cip == headers.ipv4.dst && user_metadata.temp_sip == headers.dns_ip.rdata)) {
                        cip_table_2.write(user_metadata.index_2, headers.ipv4.dst);
                        sip_table_2.write(user_metadata.index_2, headers.dns_ip.rdata);
                        timestamp_table_2.write(user_metadata.index_2, (bit<32>)standard_metadata.ingress_global_timestamp);
                        name_table_2.write(user_metadata.index_2, user_metadata.domain_id);
                        user_metadata.already_matched = 1;
                    }
                }

                // access table 3
                if (user_metadata.already_matched == 0) {
                    cip_table_3.read(user_metadata.temp_cip, user_metadata.index_3);
                    sip_table_3.read(user_metadata.temp_sip, user_metadata.index_3);
                    timestamp_table_3.read(user_metadata.temp_timestamp, user_metadata.index_3);
                    if (user_metadata.temp_timestamp == 0 || user_metadata.temp_timestamp + TIMEOUT < (bit<32>)standard_metadata.ingress_global_timestamp || (user_metadata.temp_cip == headers.ipv4.dst && user_metadata.temp_sip == headers.dns_ip.rdata)) {
                        cip_table_3.write(user_metadata.index_3, headers.ipv4.dst);
                        sip_table_3.write(user_metadata.index_3, headers.dns_ip.rdata);
                        timestamp_table_3.write(user_metadata.index_3, (bit<32>)standard_metadata.ingress_global_timestamp);
                        name_table_3.write(user_metadata.index_3, user_metadata.domain_id);
                        user_metadata.already_matched = 1;
                    }
                }

                // access table 4
                if (user_metadata.already_matched == 0) {
                    cip_table_4.read(user_metadata.temp_cip, user_metadata.index_4);
                    sip_table_4.read(user_metadata.temp_sip, user_metadata.index_4);
                    timestamp_table_4.read(user_metadata.temp_timestamp, user_metadata.index_4);
                    if (user_metadata.temp_timestamp == 0 || user_metadata.temp_timestamp + TIMEOUT < (bit<32>)standard_metadata.ingress_global_timestamp || (user_metadata.temp_cip == headers.ipv4.dst && user_metadata.temp_sip == headers.dns_ip.rdata)) {
                        cip_table_4.write(user_metadata.index_4, headers.ipv4.dst);
                        sip_table_4.write(user_metadata.index_4, headers.dns_ip.rdata);
                        timestamp_table_4.write(user_metadata.index_4, (bit<32>)standard_metadata.ingress_global_timestamp);
                        name_table_4.write(user_metadata.index_4, user_metadata.domain_id);
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
        else if(user_metadata.domain_parsed == 1) {
            user_metadata.q1_id = 0;
            user_metadata.q2_id = 0;
            user_metadata.q3_id = 0;
            user_metadata.q4_id = 0;
            user_metadata.q5_id = 0;
            user_metadata.domain_id = 0;
            user_metadata.matched_domain = 0;

            tlsknown_domain_list_q1.apply();
            tlsknown_domain_list_q2.apply();
            tlsknown_domain_list_q3.apply();
            tlsknown_domain_list_q4.apply();
            tlsknown_domain_list_q5.apply();
            tlsmatch_known_domain_list.apply();

            if (user_metadata.matched_domain == 1) {

                // Increment total tls queries for this domain name
                tls_total_queried.read(user_metadata.temp_total_tls, user_metadata.domain_id);
                tls_total_queried.write(user_metadata.domain_id, user_metadata.temp_total_tls + 1);

                if (headers.ipv4.src > headers.ipv4.dst) {
                    hash(user_metadata.index_1, HashAlgorithm.crc16, HASH_TABLE_BASE, {headers.ipv4.src, 7w11, headers.ipv4.dst}, HASH_TABLE_MAX);
                    hash(user_metadata.index_2, HashAlgorithm.crc16, HASH_TABLE_BASE, {3w5, headers.ipv4.src, 5w3, headers.ipv4.dst}, HASH_TABLE_MAX);
                    hash(user_metadata.index_3, HashAlgorithm.crc16, HASH_TABLE_BASE, {2w0, headers.ipv4.src, 1w1, headers.ipv4.dst}, HASH_TABLE_MAX);
                    hash(user_metadata.index_4, HashAlgorithm.crc16, HASH_TABLE_BASE, {3w7, headers.ipv4.src, 5w12, headers.ipv4.dst}, HASH_TABLE_MAX);
                }
                else {
                    hash(user_metadata.index_1, HashAlgorithm.crc16, HASH_TABLE_BASE, {headers.ipv4.dst, 7w11, headers.ipv4.src}, HASH_TABLE_MAX);
                    hash(user_metadata.index_2, HashAlgorithm.crc16, HASH_TABLE_BASE, {3w5, headers.ipv4.dst, 5w3, headers.ipv4.src}, HASH_TABLE_MAX);
                    hash(user_metadata.index_3, HashAlgorithm.crc16, HASH_TABLE_BASE, {2w0, headers.ipv4.dst, 1w1, headers.ipv4.src}, HASH_TABLE_MAX);
                    hash(user_metadata.index_4, HashAlgorithm.crc16, HASH_TABLE_BASE, {3w7, headers.ipv4.dst, 5w12, headers.ipv4.src}, HASH_TABLE_MAX);
                }

                user_metadata.already_matched = 0;
                // access table 1
                cip_table_1.read(user_metadata.temp_cip, user_metadata.index_1);
                sip_table_1.read(user_metadata.temp_sip, user_metadata.index_1);
                timestamp_table_1.read(user_metadata.temp_timestamp, user_metadata.index_1);
                if (user_metadata.temp_timestamp == 0 || user_metadata.temp_timestamp + TIMEOUT < (bit<32>)standard_metadata.ingress_global_timestamp || (user_metadata.temp_cip == headers.ipv4.src && user_metadata.temp_sip == headers.ipv4.dst)) {
                    cip_table_1.write(user_metadata.index_1, headers.ipv4.src);
                    sip_table_1.write(user_metadata.index_1, headers.ipv4.dst);
                    timestamp_table_1.write(user_metadata.index_1, (bit<32>)standard_metadata.ingress_global_timestamp);
                    name_table_1.write(user_metadata.index_1, user_metadata.domain_id);
                    user_metadata.already_matched = 1;
                }

                // access table 2
                if (user_metadata.already_matched == 0) {
                    cip_table_2.read(user_metadata.temp_cip, user_metadata.index_2);
                    sip_table_2.read(user_metadata.temp_sip, user_metadata.index_2);
                    timestamp_table_2.read(user_metadata.temp_timestamp, user_metadata.index_2);
                    if (user_metadata.temp_timestamp == 0 || user_metadata.temp_timestamp + TIMEOUT < (bit<32>)standard_metadata.ingress_global_timestamp || (user_metadata.temp_cip == headers.ipv4.src && user_metadata.temp_sip == headers.ipv4.dst)) {
                        cip_table_2.write(user_metadata.index_2, headers.ipv4.src);
                        sip_table_2.write(user_metadata.index_2, headers.ipv4.dst);
                        timestamp_table_2.write(user_metadata.index_2, (bit<32>)standard_metadata.ingress_global_timestamp);
                        name_table_2.write(user_metadata.index_2, user_metadata.domain_id);
                        user_metadata.already_matched = 1;
                    }
                }

                // access table 3
                if (user_metadata.already_matched == 0) {
                    cip_table_3.read(user_metadata.temp_cip, user_metadata.index_3);
                    sip_table_3.read(user_metadata.temp_sip, user_metadata.index_3);
                    timestamp_table_3.read(user_metadata.temp_timestamp, user_metadata.index_3);
                    if (user_metadata.temp_timestamp == 0 || user_metadata.temp_timestamp + TIMEOUT < (bit<32>)standard_metadata.ingress_global_timestamp || (user_metadata.temp_cip == headers.ipv4.src && user_metadata.temp_sip == headers.ipv4.dst)) {
                        cip_table_3.write(user_metadata.index_3, headers.ipv4.src);
                        sip_table_3.write(user_metadata.index_3, headers.ipv4.dst);
                        timestamp_table_3.write(user_metadata.index_3, (bit<32>)standard_metadata.ingress_global_timestamp);
                        name_table_3.write(user_metadata.index_3, user_metadata.domain_id);
                        user_metadata.already_matched = 1;
                    }
                }

                // access table 4
                if (user_metadata.already_matched == 0) {
                    cip_table_4.read(user_metadata.temp_cip, user_metadata.index_4);
                    sip_table_4.read(user_metadata.temp_sip, user_metadata.index_4);
                    timestamp_table_4.read(user_metadata.temp_timestamp, user_metadata.index_4);
                    if (user_metadata.temp_timestamp == 0 || user_metadata.temp_timestamp + TIMEOUT < (bit<32>)standard_metadata.ingress_global_timestamp || (user_metadata.temp_cip == headers.ipv4.src && user_metadata.temp_sip == headers.ipv4.dst)) {
                        cip_table_4.write(user_metadata.index_4, headers.ipv4.src);
                        sip_table_4.write(user_metadata.index_4, headers.ipv4.dst);
                        timestamp_table_4.write(user_metadata.index_4, (bit<32>)standard_metadata.ingress_global_timestamp);
                        name_table_4.write(user_metadata.index_4, user_metadata.domain_id);
                        user_metadata.already_matched = 1;
                    }
                }

                if (user_metadata.already_matched == 0) {
                    // Increment total tls queries missed for this domain name
                    tls_total_missed.read(user_metadata.temp_total_missed, user_metadata.domain_id);
                    tls_total_missed.write(user_metadata.domain_id, user_metadata.temp_total_missed + 1);
                }
            }
        }
        // HANDLE NORMAL, NON-DNS PACKETS
        else if (user_metadata.is_ip == 1 && user_metadata.is_dns == 0) {

            if (headers.ipv4.src > headers.ipv4.dst) {
                hash(user_metadata.index_1, HashAlgorithm.crc16, HASH_TABLE_BASE, {headers.ipv4.src, 7w11, headers.ipv4.dst}, HASH_TABLE_MAX);
                hash(user_metadata.index_2, HashAlgorithm.crc16, HASH_TABLE_BASE, {3w5, headers.ipv4.src, 5w3, headers.ipv4.dst}, HASH_TABLE_MAX);
                hash(user_metadata.index_3, HashAlgorithm.crc16, HASH_TABLE_BASE, {2w0, headers.ipv4.src, 1w1, headers.ipv4.dst}, HASH_TABLE_MAX);
                hash(user_metadata.index_4, HashAlgorithm.crc16, HASH_TABLE_BASE, {3w7, headers.ipv4.src, 5w12, headers.ipv4.dst}, HASH_TABLE_MAX);
            }
            else {
                hash(user_metadata.index_1, HashAlgorithm.crc16, HASH_TABLE_BASE, {headers.ipv4.dst, 7w11, headers.ipv4.src}, HASH_TABLE_MAX);
                hash(user_metadata.index_2, HashAlgorithm.crc16, HASH_TABLE_BASE, {3w5, headers.ipv4.dst, 5w3, headers.ipv4.src}, HASH_TABLE_MAX);
                hash(user_metadata.index_3, HashAlgorithm.crc16, HASH_TABLE_BASE, {2w0, headers.ipv4.dst, 1w1, headers.ipv4.src}, HASH_TABLE_MAX);
                hash(user_metadata.index_4, HashAlgorithm.crc16, HASH_TABLE_BASE, {3w7, headers.ipv4.dst, 5w12, headers.ipv4.src}, HASH_TABLE_MAX);
            }

            user_metadata.already_matched = 0;

            cip_table_1.read(user_metadata.temp_cip, user_metadata.index_1);
            sip_table_1.read(user_metadata.temp_sip, user_metadata.index_1);
            if ((headers.ipv4.dst == user_metadata.temp_cip && headers.ipv4.src == user_metadata.temp_sip) || (headers.ipv4.dst == user_metadata.temp_sip && headers.ipv4.src == user_metadata.temp_cip)) {
                user_metadata.already_matched = 1;
                name_table_1.read(user_metadata.domain_id, user_metadata.index_1);
                packet_counts_table.read(user_metadata.temp_packet_counter, user_metadata.domain_id);
                byte_counts_table.read(user_metadata.temp_byte_counter, user_metadata.domain_id);
                packet_counts_table.write(user_metadata.domain_id, user_metadata.temp_packet_counter + 1);
                byte_counts_table.write(user_metadata.domain_id, user_metadata.temp_byte_counter + (bit<32>)headers.ipv4.len);
                timestamp_table_1.write(user_metadata.index_1, (bit<32>)standard_metadata.ingress_global_timestamp);
            }

            if (user_metadata.already_matched == 0) {
                cip_table_2.read(user_metadata.temp_cip, user_metadata.index_2);
                sip_table_2.read(user_metadata.temp_sip, user_metadata.index_2);
                if ((headers.ipv4.dst == user_metadata.temp_cip && headers.ipv4.src == user_metadata.temp_sip) || (headers.ipv4.dst == user_metadata.temp_sip && headers.ipv4.src == user_metadata.temp_cip)) {
                    user_metadata.already_matched = 1;
                    name_table_2.read(user_metadata.domain_id, user_metadata.index_2);
                    packet_counts_table.read(user_metadata.temp_packet_counter, user_metadata.domain_id);
                    byte_counts_table.read(user_metadata.temp_byte_counter, user_metadata.domain_id);
                    packet_counts_table.write(user_metadata.domain_id, user_metadata.temp_packet_counter + 1);
                    byte_counts_table.write(user_metadata.domain_id, user_metadata.temp_byte_counter + (bit<32>)headers.ipv4.len);
                    timestamp_table_2.write(user_metadata.index_2, (bit<32>)standard_metadata.ingress_global_timestamp);
                }
            }
            
            if (user_metadata.already_matched == 0) {
                cip_table_3.read(user_metadata.temp_cip, user_metadata.index_3);
                sip_table_3.read(user_metadata.temp_sip, user_metadata.index_3);
                if ((headers.ipv4.dst == user_metadata.temp_cip && headers.ipv4.src == user_metadata.temp_sip) || (headers.ipv4.dst == user_metadata.temp_sip && headers.ipv4.src == user_metadata.temp_cip)) {
                    user_metadata.already_matched = 1;
                    name_table_3.read(user_metadata.domain_id, user_metadata.index_3);
                    packet_counts_table.read(user_metadata.temp_packet_counter, user_metadata.domain_id);
                    byte_counts_table.read(user_metadata.temp_byte_counter, user_metadata.domain_id);
                    packet_counts_table.write(user_metadata.domain_id, user_metadata.temp_packet_counter + 1);
                    byte_counts_table.write(user_metadata.domain_id, user_metadata.temp_byte_counter + (bit<32>)headers.ipv4.len);
                    timestamp_table_3.write(user_metadata.index_3, (bit<32>)standard_metadata.ingress_global_timestamp);
                }
            }

            if (user_metadata.already_matched == 0) {
                cip_table_4.read(user_metadata.temp_cip, user_metadata.index_4);
                sip_table_4.read(user_metadata.temp_sip, user_metadata.index_4);
                if ((headers.ipv4.dst == user_metadata.temp_cip && headers.ipv4.src == user_metadata.temp_sip) || (headers.ipv4.dst == user_metadata.temp_sip && headers.ipv4.src == user_metadata.temp_cip)) {
                    name_table_4.read(user_metadata.domain_id, user_metadata.index_4);
                    packet_counts_table.read(user_metadata.temp_packet_counter, user_metadata.domain_id);
                    byte_counts_table.read(user_metadata.temp_byte_counter, user_metadata.domain_id);
                    packet_counts_table.write(user_metadata.domain_id, user_metadata.temp_packet_counter + 1);
                    byte_counts_table.write(user_metadata.domain_id, user_metadata.temp_byte_counter + (bit<32>)headers.ipv4.len);
                    timestamp_table_4.write(user_metadata.index_4, (bit<32>)standard_metadata.ingress_global_timestamp);
                }
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