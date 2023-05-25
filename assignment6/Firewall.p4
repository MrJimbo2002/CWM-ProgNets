/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#define MAX_DDos_Size 131072
#define DDoS_threshold 200

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        /* TODO: add parser logic */
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.type) {
        0x800 : parse_ipv4;
        
        transition accept;
        }
    }
    
    
    
    state parse_ipv4{
    	packet.extract(hdr.ipv4);
    	transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
                  
//*The majoy appending function of my firewall corresponds to the DDOS attact protection utilising registers as temporary store of 
count min sketch values. The settling quota of maximum number of a specific IP address is defined as 200 and cms refers to count min sketch
as abbreviation below.


                register<bit<32>>(1024) occSlots1;
		register<bit<32>>(1024) occSlots2;
		register<bit<32>>(1024) occSlots3;
		register<bit<1>>(MAX_DDoS_SIZE) cms1_0;
		register<bit<1>>(MAX_DDoS_SIZE) cms1_1;
		register<bit<1>>(MAX_DDoS_SIZE) cms1_2;
		register<bit<1>>(MAX_DDoS_SIZE) cms1_3;
		register<bit<1>>(MAX_DDoS_SIZE) cms1_4;
		register<bit<1>>(MAX_DDoS_SIZE) cms1_5;
		register<bit<1>>(MAX_DDoS_SIZE) cms1_6;
		register<bit<1>>(MAX_DDoS_SIZE) cms1_7;
		
		register<bit<1>>(MAX_DDoS_SIZE) cms2_0;
		register<bit<1>>(MAX_DDoS_SIZE) cms2_1;
		register<bit<1>>(MAX_DDoS_SIZE) cms2_2;
		register<bit<1>>(MAX_DDoS_SIZE) cms2_3;
		register<bit<1>>(MAX_DDoS_SIZE) cms2_4;
		register<bit<1>>(MAX_DDoS_SIZE) cms2_5;
		register<bit<1>>(MAX_DDoS_SIZE) cms2_6;
		register<bit<1>>(MAX_DDoS_SIZE) cms2_7;

		register<bit<1>>(MAX_DDoS_SIZE) cms3_0;
		register<bit<1>>(MAX_DDoS_SIZE) cms3_1;
		register<bit<1>>(MAX_DDoS_SIZE) cms3_2;
		register<bit<1>>(MAX_DDoS_SIZE) cms3_3;
		register<bit<1>>(MAX_DDoS_SIZE) cms3_4;
		register<bit<1>>(MAX_DDoS_SIZE) cms3_5;
		register<bit<1>>(MAX_DDoS_SIZE) cms3_6;
		register<bit<1>>(MAX_DDoS_SIZE) cms3_7;
		
		
		
                  
                  
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        /* TODO: fill out code in action body */
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard.metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        /* TODO: fix ingress control logic
         *  - ipv4_lpm should be applied only when IPv4 header is valid
         */
	 
	 //* Index in Count-min Sketch (Size 1024)
	 
	 
        if(hdr.ipv4.isValid()){ 
            ipv4_lpm.apply();
        }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        /* TODO: add deparser logic */
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
