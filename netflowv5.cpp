/*
 * ISA project
 * Author: Tomáš Matuš
 * Login: xmatus37
 * Date: 06.11.2022
 */

#include "netflowv5.hpp"

Netflowv5::Netflowv5(const struct pcap_pkthdr *header, const u_char *packet, uint32_t time_ms)
{
    const struct ip *ip = (struct ip*)(packet + sizeof(struct ether_header));
    srcaddr = ntohl(ip->ip_src.s_addr);
    dstaddr = ntohl(ip->ip_dst.s_addr);

    uint8_t protocol = ip->ip_p;

    switch (protocol)
    {
        case PROTOCOL_TCP:
        {
            prot = PROTOCOL_TCP;
            const struct tcphdr *tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip->ip_hl * 4);
            srcport = ntohs(tcp->th_sport);
            dstport = ntohs(tcp->th_dport);
            tcp_flags = tcp->th_flags;
            break;
        }

        case PROTOCOL_UDP:
        {
            prot = PROTOCOL_UDP;
            const struct udphdr *udp = (struct udphdr*)(packet + sizeof(struct ether_header) + ip->ip_hl * 4);
            srcport = ntohs(udp->uh_sport);
            dstport = ntohs(udp->uh_dport);
            tcp_flags = 0;
            break;
        }

        case PROTOCOL_ICMP:
        {
            prot = PROTOCOL_ICMP;
            const struct icmphdr *icmp = (struct icmphdr*)(packet + sizeof(struct ether_header) + ip->ip_hl * 4);
            srcport = 0;
            // for ICMP destination port is: port = ICMP-Type * 256 + ICMP-Code
            dstport = ntohs(icmp->type * 256 + icmp->code);
            tcp_flags = 0;
            break;
        }

        default:
            // TODO
            std::cerr << "Unsupported packet\n";
            break;
    }

    d_pkts = 1;
    d_octets = ntohs(ip->ip_len);
    first = time_ms;
    last = time_ms;
    tos = ip->ip_tos;
}

void Netflowv5::pack(nf5_record_t &record)
{
    record.srcaddr = htonl(srcaddr);
    record.dstaddr = htonl(dstaddr);
    record.nexthop = htonl(nexthop);
    record.input = htons(input);
    record.output = htons(output);
    record.d_pkts = htonl(d_pkts);
    record.d_octets = htonl(d_octets);
    record.first = htonl(first);
    record.last = htonl(last);
    record.srcport = htons(srcport);
    record.dstport = htons(dstport);
    record.pad = 0;
    record.tcp_flags = tcp_flags;
    record.prot = prot;
    record.tos = tos;
    record.src_as = src_as;
    record.dst_as = dst_as;
    record.src_mask = src_mask;
    record.dst_mask = dst_mask;
    record.pad1 = 0;
}