#include <tuple>
#include <map>
#include <vector>
#include <cstring>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<unistd.h>
#include<netdb.h>

#include "netflowv5.hpp"

class FlowCache {
    private:
        // tuple<srcaddr, dstaddr, srcport, dstport, prot>
        std::map<std::tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t>, Netflowv5 *> cache;
        std::vector<nf5_record_t> buffer;

        // unix time to substract from other timers to get ms from 0 (first packet)
        uint64_t sys_uptime_ms = 0;
        // time of last export since boot ms
        uint32_t last_export_ms = 0;
        // current time ms
        uint32_t time_since_boot_ms = 0;
        uint16_t flow_sequence = 0;

        uint32_t active_timer = 60 * 1000;
        uint32_t inactive_timer = 10 * 1000;
        uint32_t max_cache_size = 1024;
        std::string collector = "127.0.0.1";
        uint16_t collector_port = 2055;

        /**
         * @brief finds expired flows to export and removes them from cache
         */
        void export_on_timer(bool export_all = false);

        /**
         * @brief prepares flow to be exported with max count checking (1-30 flows per export)
         */
        void export_flow(Netflowv5 *flow);

        /**
         * @brief exports oldest flow when cache is full
         */
        void export_oldest();

        /**
         * @brief creates flow header and records
         */
        void flush_buffer();

        /**
         * @brief sends data to collector
         */
        void send_packet(u_char *data, size_t size);

    public:
        /**
         * @brief update existing flow or add new one when it is not present in cache
         */
        void insert_update_flow(Netflowv5 *flow);

        /**
         * @brief get number of flows in flow cache
         */
        std::size_t get_cache_size();

        /**
         * @brief get time in miliseconds since sys boot time
         */
        uint32_t get_miliseconds(uint64_t s, uint64_t us);

        /**
         * @brief set cache parameters and collector information
         */
        void set_flowcache(int active, int inactive, int size, std::string collect, uint16_t port);

        /**
         * @brief export remaining flows when finished reading pcap file
         */
        void export_cache();
};
