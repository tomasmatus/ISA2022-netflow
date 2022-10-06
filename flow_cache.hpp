#include <tuple>
#include <map>

#include "netflowv5.hpp"

class FlowCache {
    private:
        // tuple<srcaddr, dstaddr, srcport, dstport, prot>
        std::map<std::tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t>, Netflowv5 *> cache;

        // unix time to substract from other timers to get ms from 0 (first packet)
        uint32_t sys_uptime_ms = 0;
        // timer to run export check every 1000ms
        uint32_t timer_ms = 0;
        uint32_t last_export_ms = 0;

        uint32_t active_timer = 60 * 1000;
        uint32_t inactive_timer = 10 * 1000;
        uint32_t max_cache_size = 1024;
        std::string collector = "127.0.0.1:2055";

        void export_on_timer();

    public:
        void insert_update_flow(
            Netflowv5 *flow
        );

        /**
         * @brief get number of flows in flow cache
         */
        std::size_t get_cache_size();

        /**
         * @brief get time in miliseconds since sys boot time
         */
        uint32_t get_miliseconds(uint32_t s, uint32_t us);

        void set_flowcache(int active, int inactive, int size, std::string collect);
};
