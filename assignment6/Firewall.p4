/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//#define MAX_DDos_Size 131072
//#define DDoS_threshold 200

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

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t { 
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> udplen;
    bit<16> udpchk;
}


//set up a global variable val in structures of metadata//
struct metadata {
            bit<32> val;
            bit<32> hit;
            }

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t	 tcp;
    udp_t	 udp;
//define protocols across all layers detected in headers/
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        /*add parser logic */
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
        0x800 : parse_ipv4;
        default: accept;
        }
    }
    
    
    
    state parse_ipv4{
    	packet.extract(hdr.ipv4);
    	transition select(hdr.ipv4.protocol){
    	
    	8w0x6: parse_tcp;
    	8w0x11:parse_udp;
    	default: accept;
    }
  }
    
    state parse_tcp{
    packet.extract(hdr.tcp);
    transition accept;
    }
    
    state parse_udp{
    packet.extract(hdr.udp);
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
                  
//The majoy appending function of my firewall corresponds to the DDOS attact protection utilising registers as temporary store of count min sketch values. 	
//The settling quota of maximum number of a specific IP address is defined as 200 and cms refers to count min sketch as abbreviation below.
//Index of Count-Min-Sketch of size 1024


    register<bit<32>>(2) r;
    	
                  
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
    
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        meta.hit = 1;
	
    //under ipv4_forward action, try to add "counters" increased by one in registers stored in global variable val.
    
       
    }
    
   
        
        
    table ipv4 {
        key = {
        
     //define all the allowed white list ipv4 source and destination address and udp source and destination port.
        
            hdr.ipv4.dstAddr: exact;
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.protocol:exact;
            hdr.udp.srcPort: exact;
            hdr.udp.dstPort : exact; 
            
            }
            
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        
        size = 1024;
        default_action = NoAction;
    }


    apply {
    
 	//ipv4 should be applied only when IPv4 header is valid//
  	meta.hit = 0;
  	
	if(meta.hit == 0){ 
            ipv4.apply();
        }
        else{
              drop();
            }
            
             
        r.read(meta.val, 0);
    	meta.val = meta.val + 1;
    	r.write(0, meta.val);
        
        if (meta.val > 100){
            drop();
        }
        else{
            ip4Addr_t temp;
            temp = hdr.ipv4.srcAddr;
            hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
            hdr.ipv4.dstAddr = temp;
            standard_metadata.egress_spec = standard_metadata.ingress_port;
        }
             
        

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
        //* add deparser logic */
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
