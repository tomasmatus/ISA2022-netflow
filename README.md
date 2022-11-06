# ISA project 2022 - Netflow

Author: Tomáš Matuš (xmatus37)

Date: 06.11.2022

## Description

Simple program for exporting internet communication using NetFlow v5 standard.
Packets read from a captured communication in a `pcap` file are aggregated into
flows and later are exported and sent to a specified collector using UDP protocol.

This flow exporter only supports TCP, UDP and ICMP communication.

## Example usage

```
./flow -f traffic.pcap -c my.collector.net:9995 -a 120 -i 160 -m 2048
```

## Files
- flow.cpp
- netflowv5.cpp, netflowv5.hpp
- flow_cache.cpp, flow_cache.hpp
- Makefile
- README.md
- manual.pdf
- flow.1