#ifndef netflowv5_hpp
#define netflowv5_hpp

#include <cstdint>
#include <iostream>

#include <pcap/pcap.h>
#include <net/ethernet.h>       // struct ethernet
#include <netinet/ether.h>      // ether_ntoa
#include <netinet/in.h>         // inet_ntoa
#include <netinet/ip.h>         // struct ip
#include <netinet/ip6.h>        // struct ip6_hdr
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/sysinfo.h>

#define BUFFLEN 64
#define PROTOCOL_ICMP 1
#define PROTOCOL_TCP 6
#define PROTOCOL_UDP 17
#define NF5_VERSION 5
#define NF5_MAX_COUNT 30

typedef struct __attribute__((packed, aligned(4)))
{
    uint32_t srcaddr;
    uint32_t dstaddr;
    uint32_t nexthop;
    uint16_t input;
    uint16_t output;
    uint32_t d_pkts;
    uint32_t d_octets;
    uint32_t first;
    uint32_t last;
    uint16_t srcport;
    uint16_t dstport;
    uint8_t pad;
    uint8_t tcp_flags;
    uint8_t prot;
    uint8_t tos;
    uint16_t src_as;
    uint16_t dst_as;
    uint8_t src_mask;
    uint8_t dst_mask;
    uint16_t pad1;
} nf5_record_t;

typedef struct __attribute__((packed, aligned(4)))
{
    uint16_t version;
    uint16_t count;
    uint32_t sys_uptime;
    uint32_t unix_secs;
    uint32_t unix_nsecs;
    uint32_t flow_sequence;
    uint8_t engine_type;
    uint8_t engine_id;
    uint16_t sampling_interval;
} nf5_header_t;

class Netflowv5 {
    public:
        uint32_t srcaddr;
        uint32_t dstaddr;
        uint32_t nexthop = 0;
        uint16_t input = 0;
        uint16_t output = 0;
        uint32_t d_pkts;
        uint32_t d_octets;
        uint32_t first;
        uint32_t last;
        uint16_t srcport;
        uint16_t dstport;
        uint8_t pad = 0;
        uint8_t tcp_flags;
        uint8_t prot;
        uint8_t tos;
        uint16_t src_as = 0;
        uint16_t dst_as = 0;
        uint8_t src_mask = 0;
        uint8_t dst_mask = 0;
        uint16_t pad1 = 0;

        Netflowv5(const struct pcap_pkthdr *pcap_hdr, const u_char *packet, u_int32_t time_ms);

        /**
         * @brief prepare flow for exporting
         *
         * @param record Netflow record
         */
        void pack(nf5_record_t &record);
};

#endif // netflowv5