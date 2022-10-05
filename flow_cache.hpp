#include <tuple>
#include <map>

#include "netflowv5.hpp"

class FlowCache {
    private:
        // tuple<srcaddr, dstaddr, srcport, dstport, prot>
        std::map<std::tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t>, Netflowv5 *> cache;

        uint32_t sys_uptime_ms = 0;

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
};