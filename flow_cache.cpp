#include "flow_cache.hpp"

void FlowCache::insert_update_flow(Netflowv5 *flow)
{
    std::tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t> flow_key = { flow->srcaddr, flow->dstaddr, flow->srcport, flow->dstport, flow->prot };

    auto search = cache.find(flow_key);
    if (search != cache.end())
    {
        // update existing flow
        search->second->d_pkts++;
        search->second->d_octets; // TODO
        search->second->last = flow->last;
        search->second->tcp_flags |= flow->tcp_flags;

        delete flow;
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

uint32_t FlowCache::get_miliseconds(uint32_t s, uint32_t us)
{
    if (!sys_uptime_ms)
    {
        sys_uptime_ms = s * 1000 + us / 1000;
        return 0;
    }

    return (s * 1000 + us / 1000) - sys_uptime_ms;
}