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
            tcp_flags = tcp->th_dport;
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
            srcport = 0;
            dstport = 0;
            tcp_flags = 0;
            break;
        }

        default:
            // TODO
            std::cerr << "Unsupported packet\n";
            break;
    }

    d_pkts = 1;
    d_octets = header->caplen - sizeof(struct ether_header);
    first = time_ms;
    last = time_ms;
    tos = ip->ip_tos;
}

void Netflowv5::pack(nf5_record_t &record)
{
    record.srcaddr = srcaddr;
    record.dstaddr = dstaddr;
    record.nexthop = nexthop;
    record.input = input;
    record.output = output;
    record.d_pkts = d_pkts;
    record.d_octets = d_octets;
    record.first = first;
    record.last = last;
    record.srcport = srcport;
    record.dstport = dstport;
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