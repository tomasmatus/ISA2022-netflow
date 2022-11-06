/*
 * ISA project
 * Author: Tomáš Matuš
 * Login: xmatus37
 * Date: 29.09.2022
 */

#include <iostream>
#include <vector>
#include <getopt.h>
#include <regex>

#include <pcap/pcap.h>
#include <net/ethernet.h>       // struct ethernet
#include <netinet/ether.h>      // ether_ntoa
#include <netinet/ip.h>         // struct ip
#include <netinet/ip6.h>        // struct ip6_hdr
#include <netinet/in.h>         // inet_ntoa
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "netflowv5.hpp"
#include "flow_cache.hpp"

#define BUFFLEN 64

FlowCache flow_cache;

uint count_char(char needle, std::string str)
{
    uint cnt = 0;
    for (auto ch : str)
    {
        if (needle == ch)
            cnt++;
    }

    return cnt;
}

int parse_collector(std::string &hostname, std::string &port)
{
    // possible valid inputs:
    // ip               127.0.0.1
    // ip:port          127.0.0.1:2055
    // ipv6             ::1
    // [ipv6]:port      [::1]:2055
    // hostname         localhost
    // hostname:port    localhost:2055
    uint cnt = count_char(':', hostname);
    if (cnt == 1)
    {
        // ip:port or hostname:port
        size_t pos = hostname.find(':');
        port = hostname.c_str() + pos + 1;
        hostname.erase(pos);
    }
    else if (cnt > 1)
    {
        // ipv6 or [ipv6]:port
        size_t pos = hostname.find(']');
        if (pos != std::string::npos)
        {
            port = hostname.c_str() + pos + 2;
            hostname.erase(pos).erase(0, 1);
        }
    }
    else // cnt == 0
    {
        // ip or hostname
    }

    return 0;
}

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
    std::string collector = "127.0.0.1";
    std::string port = "2055";
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
                // validity check
                try
                {
                    collector = optarg;
                    parse_collector(collector, port);
                }
                catch(const std::invalid_argument& e)
                {
                    std::cerr << e.what() << '\n';
                    exit(1);
                }
                break;
            
            // active timer timeout
            case 'a':
                try
                {
                    active_timer = std::stoi(optarg) * 1000;
                    if (inactive_timer <= 0)
                        throw std::invalid_argument("Active timer must be value above 0");
                }
                catch(const std::invalid_argument& e)
                {
                    std::cerr << e.what() << '\n';
                    exit(1);
                }
                break;
            // inactive timer timeout
            case 'i':
                try
                {
                    inactive_timer = std::stoi(optarg) * 1000;
                    if (inactive_timer <= 0)
                        throw std::invalid_argument("Inactive timer must be value above 0");
                }
                catch(const std::invalid_argument& e)
                {
                    std::cerr << e.what() << '\n';
                    exit(1);
                }
                break;
            
            // flow-cache size
            case 'm':
                try
                {
                    cache_size = std::stoi(optarg);
                    if (cache_size <= 0)
                        throw std::invalid_argument("Cache size must be value above 0");
                }
                catch(const std::invalid_argument& e)
                {
                    std::cerr << e.what() << '\n';
                    exit(1);
                }
                break;
            
            default:
                exit(1);
        }
    }

    flow_cache.set_flowcache(active_timer, inactive_timer, cache_size, collector, port);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *fd = pcap_open_offline (filename.c_str(), errbuf);
    if (fd == NULL)
    {
        std::cerr << "Error when opening pcap file: " << errbuf << "\n";
        return 1;
    }

    struct bpf_program fp;
    if (pcap_compile(fd, &fp, "ip and (tcp or udp or icmp)", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Can't compile filter " << errbuf << std::endl;
        return 1;
    }

    if (pcap_setfilter(fd, &fp) == -1) {
        std::cerr << "Can't set filter " << errbuf << std::endl;
        return 1;
    }

    if (pcap_loop(fd, -1, read_packet, nullptr) == PCAP_ERROR) {
        std::cerr << "pcap_loop fail: " << errbuf << std::endl;
        return 1;
    }
    pcap_freecode(&fp);
    pcap_close(fd);

    // export all remaining flows in cache
    flow_cache.export_cache();

    return 0;
}