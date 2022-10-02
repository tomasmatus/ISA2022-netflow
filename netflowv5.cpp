#include "netflowv5.hpp"

#define BUFFLEN 64
#define PROTOCOL_TCP 6
#define PROTOCOL_ICMP 8
#define PROTOCOL_UDP 17

Netflowv5::Netflowv5(const struct pcap_pkthdr *header, const u_char *packet)
{
    const struct ip *ip = (struct ip*)(packet + sizeof(struct ether_header));
    srcaddr = ntohl(ip->ip_src.s_addr);
    dstaddr = ntohl(ip->ip_dst.s_addr);

    uint8_t protocol = (ip->ip_p);
    switch (protocol)
    {
        case PROTOCOL_TCP:
        {
            prot = PROTOCOL_TCP;
            const struct tcphdr *tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip->ip_hl * 4);
            srcport = ntohs(tcp->th_sport);
            dstport = ntohs(tcp->th_dport);
            // TODO TCP flags
            break;
        }

        case PROTOCOL_UDP:
        {
            prot = PROTOCOL_UDP;
            const struct udphdr *udp = (struct udphdr*)(packet + sizeof(struct ether_header) + ip->ip_hl * 4);
            srcport = ntohs(udp->uh_sport);
            dstport = ntohs(udp->uh_dport);
            break;
        }

        case PROTOCOL_ICMP:
        {
            srcport = 0;
            dstport = 0;
        }

        default:
            break;
    }

    nexthop = 0;
    input = 0;
    output = 0;
    d_pkts = 1;
    d_octets = 0; // ??? TODO
    first = 0;
    last = 0;
    tos = ip->ip_tos;
    src_as = 0;
    dst_as = 0;
    src_mask = 0;
    dst_mask = 0;
}