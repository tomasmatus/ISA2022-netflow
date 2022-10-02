#include "flow_cache.hpp"

void FlowCache::insert_update_flow(Netflowv5 *flow)
{
    std::tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t> flow_key = { flow->srcaddr, flow->dstaddr, flow->srcport, flow->dstport, flow->prot };

    auto search = cache.find(flow_key);
    if (search != cache.end())
    {
        // update existing flow
        search->second->d_pkts++;
        search->second->d_octets;
        search->second->last = flow->last;
        search->second->tcp_flags |= flow->tcp_flags;
    }
    else
    {
        // insert new flow
        cache[flow_key] = flow;
    }
}

std::size_t FlowCache::get_cache_size()
{
    return cache.size();
}