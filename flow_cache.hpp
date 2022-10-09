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

        uint32_t active_timer = 60 * 1000;
        uint32_t inactive_timer = 10 * 1000;
        uint32_t max_cache_size = 1024;
        std::string collector = "127.0.0.1:2055";
        uint16_t flow_sequence = 0;

        void export_on_timer(bool export_all = false);

        void export_flow(Netflowv5 *flow);

        void export_oldest();

        void flush_buffer();

        void send_packet(u_char *data, size_t size);

    public:
        void insert_update_flow(Netflowv5 *flow);

        /**
         * @brief get number of flows in flow cache
         */
        std::size_t get_cache_size();

        /**
         * @brief get time in miliseconds since sys boot time
         */
        uint32_t get_miliseconds(uint64_t s, uint64_t us);

        void set_flowcache(int active, int inactive, int size, std::string collect);

        void export_cache();
};
