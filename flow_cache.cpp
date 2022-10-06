#include "flow_cache.hpp"

void FlowCache::insert_update_flow(Netflowv5 *flow)
{
    std::tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t> flow_key = { flow->srcaddr, flow->dstaddr, flow->srcport, flow->dstport, flow->prot };

    auto search = cache.find(flow_key);
    if (search != cache.end())
    {
        // update existing flow
        search->second->d_pkts++;
        search->second->d_octets += flow->d_octets;
        search->second->last = flow->last;
        search->second->tcp_flags |= flow->tcp_flags;
    }
    else
    {
        // insert new flow
        cache[flow_key] = flow;
    }

    // check export conditions
    timer_ms = flow->first - last_export_ms;
    // check if 1000ms passed since last export check
    if (timer_ms >= 1000)
    {
        // run export check
        export_on_timer();
        last_export_ms = flow->first;
        timer_ms -= 1000;
    }

    if (cache.size() >= max_cache_size)
    {
        // export oldest flow
    }

    if (search != cache.end())
        delete flow;
}

// loop all elements and export based on (in)active timers
void FlowCache::export_on_timer()
{

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

void FlowCache::set_flowcache(int active, int inactive, int size, std::string collect)
{
    active_timer = active;
    inactive_timer = inactive;
    max_cache_size = size;
    collector = collect;
}