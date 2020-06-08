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

header tls_h {
    bit<40> rheader;
    bit<8> handshaketype;
    bit<24> handshakelength;
    bit<16> clientversion;
    bit<256> clientrandom;
    bit<8> sessionid;
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
    domain_byte q1_0;
    domain_byte q1_11;
    domain_byte q1_12;
    domain_byte q1_13;
    domain_byte q1_14;
    domain_byte q1_15;
    domain_byte q1_16;

    domain_byte q2_1;
    domain_byte q2_2;
    domain_byte q2_3;
    domain_byte q2_4;
    domain_byte q2_5;
    domain_byte q2_6;
    domain_byte q2_7;
    domain_byte q2_8;
    domain_byte q2_9;
    domain_byte q2_0;
    domain_byte q2_11;
    domain_byte q2_12;
    domain_byte q2_13;
    domain_byte q2_14;
    domain_byte q2_15;
    domain_byte q2_16;

    domain_byte q3_1;
    domain_byte q3_2;
    domain_byte q3_3;
    domain_byte q3_4;
    domain_byte q3_5;
    domain_byte q3_6;
    domain_byte q3_7;
    domain_byte q3_8;
    domain_byte q3_9;
    domain_byte q3_0;
    domain_byte q3_11;
    domain_byte q3_12;
    domain_byte q3_13;
    domain_byte q3_14;
    domain_byte q3_15;
    domain_byte q3_16;

    domain_byte q4_1;
    domain_byte q4_2;
    domain_byte q4_3;
    domain_byte q4_4;
    domain_byte q4_5;
    domain_byte q4_6;
    domain_byte q4_7;
    domain_byte q4_8;
    domain_byte q4_9;
    domain_byte q4_0;
    domain_byte q4_11;
    domain_byte q4_12;
    domain_byte q4_13;
    domain_byte q4_14;
    domain_byte q4_15;
}

// user defined metadata: can be used to share information between
// TopParser, TopPipe, and TopDeparser 
struct user_metadata_t {
	bit<1> is_clienthello;
	bit<1> is_ip;
    bit<1> domain_parsed;
    bit<16> domain_chars_parsed;

    bit<1> matched_domain;
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

    bit<32> temp_total_tls;
    bit<32> temp_total_missed;
}

// parsers
parser TopParser(packet_in pkt,
           out Parsed_packet p,
           inout user_metadata_t user_metadata,
           inout standard_metadata_t standard_metadata) {
    state start {
        pkt.extract(p.ethernet);
        // These are set appropriately in the TopPipe.
		user_metadata.is_clienthello = 0;
		user_metadata.is_ip = 0;
        user_metadata.domain_parsed = 0;

        transition select(p.ethernet.etherType) {
			0x800: parse_ip;
			default: accept;
		}
    }

	state parse_ip {
        pkt.extract(p.ipv4);

		user_metadata.is_ip = 1;
		transition select(p.ipv4.proto) {
			6: parse_tcp;
			default: accept;
		}
	}

	state parse_tls {
        pkt.extract(p.tcp);
        pkt.extract(p.tls);

		transition select(p.tls.handshaketype) { // 1 refers to client hello
            1: parse_tls_extra;
            default: accept;
		}
	}

    state parse_tls_extra {
        user_metadata.is_clienthello = 1;

        pkt.extract(p.tlscipher);
        pkt.advance((bit<32>) (8 * p.tlscipher.ciphersuitelength));
        pkt.extract(p.tlscompression);
        pkt.advance((bit<32>) (8 * p.tlscompression.compressionmethodslength));

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
        pkt.advance((bit<32>) (8 * p.tlsextension.extensionlength));

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

        pkt.q1_1.char = 0;
        pkt.q1_2.char = 0;
        pkt.q1_3.char = 0;
        pkt.q1_4.char = 0;
        pkt.q1_5.char = 0;
        pkt.q1_6.char = 0;
        pkt.q1_7.char = 0;
        pkt.q1_8.char = 0;
        pkt.q1_9.char = 0;
        pkt.q1_10.char = 0;
        pkt.q1_11.char = 0;
        pkt.q1_12.char = 0;
        pkt.q1_13.char = 0;
        pkt.q1_14.char = 0;
        pkt.q1_15.char = 0;
        pkt.q1_16.char = 0;

        pkt.q2_1.char = 0;
        pkt.q2_2.char = 0;
        pkt.q2_3.char = 0;
        pkt.q2_4.char = 0;
        pkt.q2_5.char = 0;
        pkt.q2_6.char = 0;
        pkt.q2_7.char = 0;
        pkt.q2_8.char = 0;
        pkt.q2_9.char = 0;
        pkt.q2_10.char = 0;
        pkt.q2_11.char = 0;
        pkt.q2_12.char = 0;
        pkt.q2_13.char = 0;
        pkt.q2_14.char = 0;
        pkt.q2_15.char = 0;
        pkt.q2_16.char = 0;

        pkt.q3_1.char = 0;
        pkt.q3_2.char = 0;
        pkt.q3_3.char = 0;
        pkt.q3_4.char = 0;
        pkt.q3_5.char = 0;
        pkt.q3_6.char = 0;
        pkt.q3_7.char = 0;
        pkt.q3_8.char = 0;
        pkt.q3_9.char = 0;
        pkt.q3_10.char = 0;
        pkt.q3_11.char = 0;
        pkt.q3_12.char = 0;
        pkt.q3_13.char = 0;
        pkt.q3_14.char = 0;
        pkt.q3_15.char = 0;
        pkt.q3_16.char = 0;

        pkt.q4_1.char = 0;
        pkt.q4_2.char = 0;
        pkt.q4_3.char = 0;
        pkt.q4_4.char = 0;
        pkt.q4_5.char = 0;
        pkt.q4_6.char = 0;
        pkt.q4_7.char = 0;
        pkt.q4_8.char = 0;
        pkt.q4_9.char = 0;
        pkt.q4_10.char = 0;
        pkt.q4_11.char = 0;
        pkt.q4_12.char = 0;
        pkt.q4_13.char = 0;
        pkt.q4_14.char = 0;
        pkt.q4_15.char = 0;

        transition parse_q1_1;
    }

    state parse_q1_1 {
        pkt.extract(p.q1_1);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_1.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_2;
        }
    }
    state parse_q1_2 {
        pkt.extract(p.q1_2);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_2.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_3;
        }
    }
    state parse_q1_3 {
        pkt.extract(p.q1_3);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_3.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_4;
        }
    }
    state parse_q1_4 {
        pkt.extract(p.q1_4);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_4.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_5;
        }
    }
    state parse_q1_5 {
        pkt.extract(p.q1_5);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_5.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_6;
        }
    }
    state parse_q1_6 {
        pkt.extract(p.q1_6);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_6.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_7;
        }
    }
    state parse_q1_7 {
        pkt.extract(p.q1_7);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_7.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_8;
        }
    }
    state parse_q1_8 {
        pkt.extract(p.q1_8);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_8.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_9;
        }
    }
    state parse_q1_9 {
        pkt.extract(p.q1_9);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_9.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_10;
        }
    }
    state parse_q1_10 {
        pkt.extract(p.q1_10);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_10.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_11;
        }
    }
    state parse_q1_11 {
        pkt.extract(p.q1_11);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_11.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_12;
        }
    }
    state parse_q1_12 {
        pkt.extract(p.q1_12);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_12.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_13;
        }
    }
    state parse_q1_13 {
        pkt.extract(p.q1_13);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_13.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_14;
        }
    }
    state parse_q1_14 {
        pkt.extract(p.q1_14);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_14.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_15;
        }
    }
    state parse_q1_15 {
        pkt.extract(p.q1_15);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_15.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_q1_16;
        }
    }
    state parse_q1_16 {
        pkt.extract(p.q1_16);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q1_16.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q1_end;
            false: parse_failure;
        }
    }
    state parse_q1_end {
        transition select(user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: accept;
            false: parse_q2_1;
        }
    }

    state parse_q2_1 {
        pkt.extract(p.q2_1);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_1.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_2;
        }
    }
    state parse_q2_2 {
        pkt.extract(p.q2_2);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_2.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_3;
        }
    }
    state parse_q2_3 {
        pkt.extract(p.q2_3);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_3.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_4;
        }
    }
    state parse_q2_4 {
        pkt.extract(p.q2_4);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_4.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_5;
        }
    }
    state parse_q2_5 {
        pkt.extract(p.q2_5);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_5.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_6;
        }
    }
    state parse_q2_6 {
        pkt.extract(p.q2_6);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_6.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_7;
        }
    }
    state parse_q2_7 {
        pkt.extract(p.q2_7);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_7.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_8;
        }
    }
    state parse_q2_8 {
        pkt.extract(p.q2_8);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_8.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_9;
        }
    }
    state parse_q2_9 {
        pkt.extract(p.q2_9);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_9.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_10;
        }
    }
    state parse_q2_10 {
        pkt.extract(p.q2_10);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_10.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_11;
        }
    }
    state parse_q2_11 {
        pkt.extract(p.q2_11);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_11.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_12;
        }
    }
    state parse_q2_12 {
        pkt.extract(p.q2_12);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_12.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_13;
        }
    }
    state parse_q2_13 {
        pkt.extract(p.q2_13);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_13.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_14;
        }
    }
    state parse_q2_14 {
        pkt.extract(p.q2_14);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_14.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_15;
        }
    }
    state parse_q2_15 {
        pkt.extract(p.q2_15);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_15.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_q2_16;
        }
    }
    state parse_q2_16 {
        pkt.extract(p.q2_16);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q2_16.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q2_end;
            false: parse_failure;
        }
    }
    state parse_q2_end {
        transition select(user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: accept;
            false: parse_q3_1;
        }
    }

    state parse_q3_1 {
        pkt.extract(p.q3_1);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_1.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_2;
        }
    }
    state parse_q3_2 {
        pkt.extract(p.q3_2);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_2.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_3;
        }
    }
    state parse_q3_3 {
        pkt.extract(p.q3_3);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_3.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_4;
        }
    }
    state parse_q3_4 {
        pkt.extract(p.q3_4);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_4.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_5;
        }
    }
    state parse_q3_5 {
        pkt.extract(p.q3_5);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_5.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_6;
        }
    }
    state parse_q3_6 {
        pkt.extract(p.q3_6);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_6.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_7;
        }
    }
    state parse_q3_7 {
        pkt.extract(p.q3_7);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_7.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_8;
        }
    }
    state parse_q3_8 {
        pkt.extract(p.q3_8);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_8.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_9;
        }
    }
    state parse_q3_9 {
        pkt.extract(p.q3_9);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_9.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_10;
        }
    }
    state parse_q3_10 {
        pkt.extract(p.q3_10);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_10.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_11;
        }
    }
    state parse_q3_11 {
        pkt.extract(p.q3_11);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_11.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_12;
        }
    }
    state parse_q3_12 {
        pkt.extract(p.q3_12);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_12.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_13;
        }
    }
    state parse_q3_13 {
        pkt.extract(p.q3_13);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_13.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_14;
        }
    }
    state parse_q3_14 {
        pkt.extract(p.q3_14);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_14.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_15;
        }
    }
    state parse_q3_15 {
        pkt.extract(p.q3_15);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_15.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_q3_16;
        }
    }
    state parse_q3_16 {
        pkt.extract(p.q3_16);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q3_16.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q3_end;
            false: parse_failure;
        }
    }
    state parse_q3_end {
        transition select(user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: accept;
            false: parse_q4_1;
        }
    }

    state parse_q4_1 {
        pkt.extract(p.q4_1);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_1.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_2;
        }
    }
    state parse_q4_2 {
        pkt.extract(p.q4_2);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_2.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_3;
        }
    }
    state parse_q4_3 {
        pkt.extract(p.q4_3);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_3.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_4;
        }
    }
    state parse_q4_4 {
        pkt.extract(p.q4_4);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_4.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_5;
        }
    }
    state parse_q4_5 {
        pkt.extract(p.q4_5);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_5.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_6;
        }
    }
    state parse_q4_6 {
        pkt.extract(p.q4_6);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_6.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_7;
        }
    }
    state parse_q4_7 {
        pkt.extract(p.q4_7);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_7.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_8;
        }
    }
    state parse_q4_8 {
        pkt.extract(p.q4_8);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_8.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_9;
        }
    }
    state parse_q4_9 {
        pkt.extract(p.q4_9);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_9.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_10;
        }
    }
    state parse_q4_10 {
        pkt.extract(p.q4_10);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_10.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_11;
        }
    }
    state parse_q4_11 {
        pkt.extract(p.q4_11);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_11.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_12;
        }
    }
    state parse_q4_12 {
        pkt.extract(p.q4_12);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_12.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_13;
        }
    }
    state parse_q4_13 {
        pkt.extract(p.q4_13);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_13.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_14;
        }
    }
    state parse_q4_14 {
        pkt.extract(p.q4_14);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_14.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_q4_15;
        }
    }
    state parse_q4_15 {
        pkt.extract(p.q4_15);
        
        user_metadata.domain_chars_parsed = user_metadata.domain_chars_parsed + 1;

        transition select(p.q4_15.char == 0x2e || user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: parse_q4_end;
            false: parse_failure
        }
    }
    state parse_q4_end {
        transition select(user_metadata.domain_chars_parsed >= user_metadata.tlsdomainheader.domainlength) {
            true: accept;
            false: parse_failure;
        }
    }

    state parse_failure {
        user_metadata.domain_parsed = 0;
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
    register<bit<32>>(TABLE_SIZE) tls_cip_table_1;
    register<bit<32>>(TABLE_SIZE) tls_sip_table_1;
    register<bit<32>>(TABLE_SIZE) tls_name_table_1;
    register<bit<32>>(TABLE_SIZE) tls_timestamp_table_1;

    register<bit<32>>(TABLE_SIZE) tls_cip_table_2;
    register<bit<32>>(TABLE_SIZE) tls_sip_table_2;
    register<bit<32>>(TABLE_SIZE) tls_name_table_2;
    register<bit<32>>(TABLE_SIZE) tls_timestamp_table_2;

    register<bit<32>>(TABLE_SIZE) tls_cip_table_3;
    register<bit<32>>(TABLE_SIZE) tls_sip_table_3;
    register<bit<32>>(TABLE_SIZE) tls_name_table_3;
    register<bit<32>>(TABLE_SIZE) tls_timestamp_table_3;

    register<bit<32>>(TABLE_SIZE) tls_cip_table_4;
    register<bit<32>>(TABLE_SIZE) tls_sip_table_4;
    register<bit<32>>(TABLE_SIZE) tls_name_table_4;
    register<bit<32>>(TABLE_SIZE) tls_timestamp_table_4;

    // REGISTER ARRAY FOR COLLECTING COUNTS ON TRAFFIC WITH KNOWN DOMAINS
    register<bit<32>>(NUM_KNOWN_DOMAINS) packet_counts_table;
    register<bit<32>>(NUM_KNOWN_DOMAINS) byte_counts_table;

    // REGISTER ARRAY FOR KEEPING TRACK OF OVERFLOW TLS CLIENT HELLOS
    register<bit<32>>(NUM_KNOWN_DOMAINS) tls_total_queried;
    register<bit<32>>(NUM_KNOWN_DOMAINS) tls_total_missed;


    action match_domain(known_domain_id id) {
        user_metadata.domain_id = id;
        user_metadata.matched_domain = 1;
    }

    table known_domain_list {
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
        }

        actions = {
            match_domain;
            NoAction;
        }
        size = NUM_KNOWN_DOMAINS;
        default_action = NoAction();
    }

    apply {
        if(user_metadata.domain_parsed == 1) {
            user_metadata.domain_id = 0;
            user_metadata.matched_domain = 0;

            known_domain_list.apply();

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
                tls_cip_table_1.read(user_metadata.temp_cip, user_metadata.index_1);
                tls_sip_table_1.read(user_metadata.temp_sip, user_metadata.index_1);
                tls_timestamp_table_1.read(user_metadata.temp_timestamp, user_metadata.index_1);
                if (user_metadata.temp_timestamp == 0 || user_metadata.temp_timestamp + TIMEOUT < (bit<32>)standard_metadata.ingress_global_timestamp || (user_metadata.temp_cip == headers.ipv4.src && user_metadata.temp_sip == headers.ipv4.dst)) {
                    tls_cip_table_1.write(user_metadata.index_1, headers.ipv4.src);
                    tls_sip_table_1.write(user_metadata.index_1, headers.ipv4.dst);
                    tls_timestamp_table_1.write(user_metadata.index_1, (bit<32>)standard_metadata.ingress_global_timestamp);
                    tls_name_table_1.write(user_metadata.index_1, user_metadata.domain_id);
                    user_metadata.already_matched = 1;
                }

                // access table 2
                if (user_metadata.already_matched == 0) {
                    tls_cip_table_2.read(user_metadata.temp_cip, user_metadata.index_2);
                    tls_sip_table_2.read(user_metadata.temp_sip, user_metadata.index_2);
                    tls_timestamp_table_2.read(user_metadata.temp_timestamp, user_metadata.index_2);
                    if (user_metadata.temp_timestamp == 0 || user_metadata.temp_timestamp + TIMEOUT < (bit<32>)standard_metadata.ingress_global_timestamp || (user_metadata.temp_cip == headers.ipv4.src && user_metadata.temp_sip == headers.ipv4.dst)) {
                        tls_cip_table_2.write(user_metadata.index_2, headers.ipv4.src);
                        tls_sip_table_2.write(user_metadata.index_2, headers.ipv4.dst);
                        tls_timestamp_table_2.write(user_metadata.index_2, (bit<32>)standard_metadata.ingress_global_timestamp);
                        tls_name_table_2.write(user_metadata.index_2, user_metadata.domain_id);
                        user_metadata.already_matched = 1;
                    }
                }

                // access table 3
                if (user_metadata.already_matched == 0) {
                    tls_cip_table_3.read(user_metadata.temp_cip, user_metadata.index_3);
                    tls_sip_table_3.read(user_metadata.temp_sip, user_metadata.index_3);
                    tls_timestamp_table_3.read(user_metadata.temp_timestamp, user_metadata.index_3);
                    if (user_metadata.temp_timestamp == 0 || user_metadata.temp_timestamp + TIMEOUT < (bit<32>)standard_metadata.ingress_global_timestamp || (user_metadata.temp_cip == headers.ipv4.src && user_metadata.temp_sip == headers.ipv4.dst)) {
                        tls_cip_table_3.write(user_metadata.index_3, headers.ipv4.src);
                        tls_sip_table_3.write(user_metadata.index_3, headers.ipv4.dst);
                        tls_timestamp_table_3.write(user_metadata.index_3, (bit<32>)standard_metadata.ingress_global_timestamp);
                        tls_name_table_3.write(user_metadata.index_3, user_metadata.domain_id);
                        user_metadata.already_matched = 1;
                    }
                }

                // access table 4
                if (user_metadata.already_matched == 0) {
                    tls_cip_table_4.read(user_metadata.temp_cip, user_metadata.index_4);
                    tls_sip_table_4.read(user_metadata.temp_sip, user_metadata.index_4);
                    tls_timestamp_table_4.read(user_metadata.temp_timestamp, user_metadata.index_4);
                    if (user_metadata.temp_timestamp == 0 || user_metadata.temp_timestamp + TIMEOUT < (bit<32>)standard_metadata.ingress_global_timestamp || (user_metadata.temp_cip == headers.ipv4.src && user_metadata.temp_sip == headers.ipv4.dst)) {
                        tls_cip_table_4.write(user_metadata.index_4, headers.ipv4.src);
                        tls_sip_table_4.write(user_metadata.index_4, headers.ipv4.dst);
                        tls_timestamp_table_4.write(user_metadata.index_4, (bit<32>)standard_metadata.ingress_global_timestamp);
                        tls_name_table_4.write(user_metadata.index_4, user_metadata.domain_id);
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
        // HANDLE NORMAL, NON-TLS CLIENT HELLO PACKETS
        else if (user_metadata.is_ip == 1 && user_metadata.is_clienthello == 0) {

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

            tls_cip_table_1.read(user_metadata.temp_cip, user_metadata.index_1);
            tls_sip_table_1.read(user_metadata.temp_sip, user_metadata.index_1);
            if ((headers.ipv4.dst == user_metadata.temp_cip && headers.ipv4.src == user_metadata.temp_sip) || (headers.ipv4.dst == user_metadata.temp_sip && headers.ipv4.src == user_metadata.temp_cip)) {
                user_metadata.already_matched = 1;
                tls_name_table_1.read(user_metadata.domain_id, user_metadata.index_1);
                packet_counts_table.read(user_metadata.temp_packet_counter, user_metadata.domain_id);
                byte_counts_table.read(user_metadata.temp_byte_counter, user_metadata.domain_id);
                packet_counts_table.write(user_metadata.domain_id, user_metadata.temp_packet_counter + 1);
                byte_counts_table.write(user_metadata.domain_id, user_metadata.temp_byte_counter + (bit<32>)headers.ipv4.len);
                tls_timestamp_table_1.write(user_metadata.index_1, (bit<32>)standard_metadata.ingress_global_timestamp);
            }

            if (user_metadata.already_matched == 0) {
                tls_cip_table_2.read(user_metadata.temp_cip, user_metadata.index_2);
                tls_sip_table_2.read(user_metadata.temp_sip, user_metadata.index_2);
                if ((headers.ipv4.dst == user_metadata.temp_cip && headers.ipv4.src == user_metadata.temp_sip) || (headers.ipv4.dst == user_metadata.temp_sip && headers.ipv4.src == user_metadata.temp_cip)) {
                    user_metadata.already_matched = 1;
                    tls_name_table_2.read(user_metadata.domain_id, user_metadata.index_2);
                    packet_counts_table.read(user_metadata.temp_packet_counter, user_metadata.domain_id);
                    byte_counts_table.read(user_metadata.temp_byte_counter, user_metadata.domain_id);
                    packet_counts_table.write(user_metadata.domain_id, user_metadata.temp_packet_counter + 1);
                    byte_counts_table.write(user_metadata.domain_id, user_metadata.temp_byte_counter + (bit<32>)headers.ipv4.len);
                    tls_timestamp_table_2.write(user_metadata.index_2, (bit<32>)standard_metadata.ingress_global_timestamp);
                }
            }

            if (user_metadata.already_matched == 0) {
                tls_cip_table_3.read(user_metadata.temp_cip, user_metadata.index_3);
                tls_sip_table_3.read(user_metadata.temp_sip, user_metadata.index_3);
                if ((headers.ipv4.dst == user_metadata.temp_cip && headers.ipv4.src == user_metadata.temp_sip) || (headers.ipv4.dst == user_metadata.temp_sip && headers.ipv4.src == user_metadata.temp_cip)) {
                    user_metadata.already_matched = 1;
                    tls_name_table_3.read(user_metadata.domain_id, user_metadata.index_3);
                    packet_counts_table.read(user_metadata.temp_packet_counter, user_metadata.domain_id);
                    byte_counts_table.read(user_metadata.temp_byte_counter, user_metadata.domain_id);
                    packet_counts_table.write(user_metadata.domain_id, user_metadata.temp_packet_counter + 1);
                    byte_counts_table.write(user_metadata.domain_id, user_metadata.temp_byte_counter + (bit<32>)headers.ipv4.len);
                    tls_timestamp_table_3.write(user_metadata.index_3, (bit<32>)standard_metadata.ingress_global_timestamp);
                }
            }

            if (user_metadata.already_matched == 0) {
                tls_cip_table_4.read(user_metadata.temp_cip, user_metadata.index_4);
                tls_sip_table_4.read(user_metadata.temp_sip, user_metadata.index_4);
                if ((headers.ipv4.dst == user_metadata.temp_cip && headers.ipv4.src == user_metadata.temp_sip) || (headers.ipv4.dst == user_metadata.temp_sip && headers.ipv4.src == user_metadata.temp_cip)) {
                    tls_name_table_4.read(user_metadata.domain_id, user_metadata.index_4);
                    packet_counts_table.read(user_metadata.temp_packet_counter, user_metadata.domain_id);
                    byte_counts_table.read(user_metadata.temp_byte_counter, user_metadata.domain_id);
                    packet_counts_table.write(user_metadata.domain_id, user_metadata.temp_packet_counter + 1);
                    byte_counts_table.write(user_metadata.domain_id, user_metadata.temp_byte_counter + (bit<32>)headers.ipv4.len);
                    tls_timestamp_table_4.write(user_metadata.index_4, (bit<32>)standard_metadata.ingress_global_timestamp);
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