#ifndef netflowv5_hpp
#define netflowv5_hpp

#include <cstdint>

#include <net/ethernet.h>       // struct ethernet
#include <netinet/ether.h>      // ether_ntoa
#include <netinet/in.h>         // inet_ntoa
#include <netinet/ip.h>         // struct ip
#include <netinet/ip6.h>        // struct ip6_hdr
#include <netinet/tcp.h>
#include <netinet/udp.h>

class Netflowv5 {
    public:
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
        uint8_t pad = 0;
        uint8_t tcp_flags;
        uint8_t prot;
        uint8_t tos;
        uint16_t src_as;
        uint16_t dst_as;
        uint8_t src_mask;
        uint8_t dst_mask;
        uint16_t pad1 = 0;

    Netflowv5(const struct pcap_pkthdr *pcap_hdr, const u_char *packet);

};

#endif // netflowv5