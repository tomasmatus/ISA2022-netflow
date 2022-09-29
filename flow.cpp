/*
 * ISA project
 * Autor: Tomáš Matuš
 * Login: xmatus37
 * Date: 29.09.2022
 */

#include <iostream>
#include <vector>
#include <getopt.h>

#include <pcap/pcap.h>

int main(int argc,
         char **argv)
{
    const char *shortopts = "f:c:a:i:m:";
    int opt = 0;
    std::string filename = "";
    std::string collector = "127.0.0.1:2055";
    int active_timer = 60;
    int inactive_timer = 10;
    int cache_size = 1024;

    while ((opt = getopt (argc, argv, shortopts)) != -1)
    {
        switch (opt)
        {
            // filename
            case 'f':
                filename = optarg;
                break;
            
            // netflow collector IP/hostname[:port]
            case 'c':
                break;
            
            // active timer timeout
            case 'a':
                active_timer = std::stoi(optarg);
                if (active_timer <= 0)
                {
                    std::cerr << "Active timer value must be above 0. Specified value: " << active_timer << "\n";
                    exit(1);
                }
                break;
            // inactive timer timeout
            case 'i':
                inactive_timer = std::stoi(optarg);
                if (inactive_timer <= 0)
                {
                    std::cerr << "Inactive timer value must be above 0. Specified value: " << inactive_timer << "\n";
                    exit(1);
                }
                break;
            
            // flow-cache size
            case 'm':
                cache_size = std::stoi(optarg);
                if (cache_size <= 0)
                {
                    std::cerr << "Cache size must be above 0. Specified value: " << cache_size << "\n";
                    exit(1);
                }
                break;
            
            default:
                exit(1);
        }
    }

    return 0;
}