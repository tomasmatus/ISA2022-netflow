/*
 * ISA project
 * Author: Tomáš Matuš
 * Login: xmatus37
 * Date: 29.09.2022
 */

#include <iostream>
#include <vector>
#include <getopt.h>

#include <pcap/pcap.h>
#include <net/ethernet.h>       // struct ethernet
#include <netinet/ether.h>      // ether_ntoa
#include <netinet/ip.h>         // struct ip
#include <netinet/ip6.h>        // struct ip6_hdr
#include <netinet/in.h>         // inet_ntoa
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "netflowv5.hpp"
#include "flow_cache.hpp"

#define BUFFLEN 64

FlowCache flow_cache;

void read_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    const struct ether_header *eth = (struct ether_header*)(packet);
    auto type = ntohs(eth->ether_type);

    if (type == ETHERTYPE_IP)
    {
        Netflowv5 *flow = new Netflowv5(header, packet, flow_cache.get_miliseconds(header->ts.tv_sec, header->ts.tv_usec));
        flow_cache.insert_update_flow(flow);
    }
}

int main(int argc, char **argv)
{
    const char *shortopts = "f:c:a:i:m:";
    int opt = 0;
    std::string filename = "-"; // "-" is a synonym for stdin
    std::string collector = "127.0.0.1:2055";
    int active_timer = 60 * 1000;
    int inactive_timer = 10 * 1000;
    int cache_size = 1024;

    while ((opt = getopt (argc, argv, shortopts)) != -1)
    {
        switch (opt)
        {
            // filename
            case 'f':
                filename = optarg;
                break;
            
            // netflow collector IP/hostname[:port]
            case 'c':
                break;
            
            // active timer timeout
            case 'a':
                active_timer = std::stoi(optarg) * 1000;
                if (active_timer <= 0)
                {
                    std::cerr << "Active timer value must be above 0. Specified value: " << active_timer << "\n";
                    exit(1);
                }
                break;
            // inactive timer timeout
            case 'i':
                inactive_timer = std::stoi(optarg) * 1000;
                if (inactive_timer <= 0)
                {
                    std::cerr << "Inactive timer value must be above 0. Specified value: " << inactive_timer << "\n";
                    exit(1);
                }
                break;
            
            // flow-cache size
            case 'm':
                cache_size = std::stoi(optarg);
                if (cache_size <= 0)
                {
                    std::cerr << "Cache size must be above 0. Specified value: " << cache_size << "\n";
                    exit(1);
                }
                break;
            
            default:
                exit(1);
        }
    }

    flow_cache.set_flowcache(active_timer, inactive_timer, cache_size, collector);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *fd = pcap_open_offline (filename.c_str(), errbuf);
    if (fd == NULL)
    {
        std::cerr << "Error when opening pcap file: " << errbuf << "\n";
        return 1;
    }
    // TODO add filter

    if (pcap_loop(fd, -1, read_packet, nullptr) == PCAP_ERROR) {
        std::cerr << "pcap_loop fail: " << errbuf << std::endl;
        return 1;
    }
    pcap_close(fd);

    // export all remaining flows in cache
    flow_cache.export_cache();

    return 0;
}
