#include "flow_cache.hpp"

void FlowCache::insert_update_flow(Netflowv5 *flow)
{
    time_since_boot_ms = flow->first;
    // check export conditions
    // check if 1000ms passed since last export check
    if (flow->first - last_export_ms >= 1000)
    {
        // run export check
        export_on_timer();
        last_export_ms = flow->first;
    }

    if (cache.size() >= max_cache_size)
    {
        // TODO export oldest flow
    }

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

    if (search != cache.end())
        delete flow;
}

// loop all elements and export based on (in)active timers
void FlowCache::export_on_timer(bool export_all)
{
    // iterating and deleting from map https://stackoverflow.com/questions/8234779/how-to-remove-from-a-map-while-iterating-it
    for (auto it = cache.cbegin(); it != cache.cend() /* not hoisted */; /* no increment */)
    {
        Netflowv5 *flow = it->second;
        if (time_since_boot_ms - flow->first > active_timer ||
            time_since_boot_ms - flow->last > inactive_timer ||
            export_all)
        {
            // export, then delete entry
            export_flow(it->second);
            cache.erase(it++);
        }
        else
        {
            ++it;
        }
    }

    flush_buffer();
}

void FlowCache::export_flow(Netflowv5 *flow)
{
    if (buffer.size() == NF5_MAX_COUNT)
        flush_buffer();

    nf5_record_t record;
    flow->pack(record);
    buffer.push_back(record);
}

void FlowCache::flush_buffer()
{
    if (buffer.size() == 0)
        return;

    size_t export_size = sizeof(nf5_header_t) + sizeof(nf5_record_t) * buffer.size();
    u_char *nf5_records_export = new u_char[export_size];

    nf5_header_t nf5_header = { .version = NF5_VERSION, .count = (uint16_t) buffer.size(), .sys_uptime = time_since_boot_ms,
                                .unix_secs = (sys_uptime_ms / 1000) + (time_since_boot_ms / 1000), .unix_nsecs = 0, .flow_sequence = 0,
                                .engine_type = 0, .engine_id = 0, .sampling_interval = 0 };

    std::memcpy(nf5_records_export, &nf5_header, sizeof(nf5_header_t));

    for (u_int32_t i = 0; i < buffer.size(); i++)
    {
       std::memcpy(nf5_records_export + sizeof(nf5_header_t) + i * sizeof(nf5_record_t), &buffer[i], sizeof(nf5_record_t));
    }

    // TODO send packet

    delete[] nf5_records_export;
    buffer.clear();
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

void FlowCache::export_cache()
{
    export_on_timer(true);
}