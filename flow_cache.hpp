#include <tuple>
#include <map>

#include "netflowv5.hpp"

class FlowCache {
    private:
        // tuple<srcaddr, dstaddr, srcport, dstport, prot>
        std::map<std::tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t>, Netflowv5 *> cache;

    public:
        void insert_update_flow(
            Netflowv5 *flow
        );

        std::size_t get_cache_size();
};