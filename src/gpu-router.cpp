#include <array>
#include <vector>
#include <iostream>
#include <string>
#include <cstring>

#include <sycl/sycl.hpp>

#include <tbb/blocked_range.h>
#include <tbb/global_control.h>
#include <tbb/flow_graph.h>
#include <pcap.h> // Include libpcap
#include "dpc_common.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include <net/if.h>

const size_t burst_size = 32;
#define PACKET_SIZE 64

int main() {
    sycl::queue q;

    std::cout << "Using device: " <<
        q.get_device().get_info<sycl::info::device::name>() << std::endl;

    int nth = std::thread::hardware_concurrency();  // Automatically detect the number of cores
    auto mp = tbb::global_control::max_allowed_parallelism;
    tbb::global_control gc(mp, nth);
    tbb::flow::graph g;

    // Input node: get packets from the socket or from the packet capture
    tbb::flow::input_node<std::vector<std::array<char, PACKET_SIZE>>> in_node{g,
        [&](tbb::flow_control& fc) -> std::vector<std::array<char, PACKET_SIZE>> {
            static pcap_t* handle = nullptr;
            static char errbuf[PCAP_ERRBUF_SIZE];

            if (!handle) {
                handle = pcap_open_offline("/root/keysight-challenge-2025/src/capture3.pcap", errbuf);
                if (!handle) {
                    std::cerr << "Error opening pcap file: " << errbuf << std::endl;
                    fc.stop();
                    return {};
                }
            }

            std::vector<std::array<char, PACKET_SIZE>> packets;
            struct pcap_pkthdr* header;
            const u_char* data;

            for (size_t i = 0; i < burst_size; ++i) {
                int ret = pcap_next_ex(handle, &header, &data);
                if (ret <= 0) { // No more packets or error
                    std::cout << "No more packets" << std::endl;
                    fc.stop();
                    break;
                }

                std::array<char, PACKET_SIZE> packet{};
                std::memcpy(packet.data(), data, std::min(static_cast<size_t>(header->caplen), static_cast<size_t>(PACKET_SIZE)));
                packets.push_back(packet);
            }

            std::cout << "Read " << packets.size() << " packets from capture1.pcap" << std::endl;
            return packets;
        }
    };

    // Parsing node: Filter packets and count protocol types
    tbb::flow::function_node<std::vector<std::array<char, PACKET_SIZE>>, std::vector<std::array<char, PACKET_SIZE>>> parse_node{
        g, tbb::flow::unlimited, [&](std::vector<std::array<char, PACKET_SIZE>> packets) {
            std::vector<std::array<char, PACKET_SIZE>> ipv4_ipv6_packets;
    
            // Counters
            size_t ipv4_count = 0, ipv6_count = 0, arp_count = 0;
            size_t icmp_count = 0, tcp_count = 0, udp_count = 0;
    
            for (const auto& packet : packets) {
                uint8_t eth_type1 = static_cast<uint8_t>(packet[12]);
                uint8_t eth_type2 = static_cast<uint8_t>(packet[13]);
    
                if (eth_type1 == 0x08 && eth_type2 == 0x00) {  // IPv4 EtherType
                    ipv4_count++;
                    ipv4_ipv6_packets.push_back(packet);
    
                    // Extract IPv4 protocol field (Ethernet 14 bytes + 9 = 23)
                    uint8_t ip_protocol = static_cast<uint8_t>(packet[23]);
                    if (ip_protocol == 0x01) icmp_count++; // ICMP
                    else if (ip_protocol == 0x06) tcp_count++; // TCP
                    else if (ip_protocol == 0x11) udp_count++; // UDP
    
                } else if (eth_type1 == 0x86 && eth_type2 == 0xDD) { // IPv6 EtherType
                    ipv6_count++;
                    ipv4_ipv6_packets.push_back(packet);
    
                    // Optional: IPv6 next header is byte 20 (Ethernet + 6), if needed
                    uint8_t next_header = static_cast<uint8_t>(packet[20]);
                    if (next_header == 0x01) icmp_count++; // ICMPv6 (simplified assumption)
                    else if (next_header == 0x06) tcp_count++;
                    else if (next_header == 0x11) udp_count++;
    
                } else if (eth_type1 == 0x08 && eth_type2 == 0x06) { // ARP EtherType
                    arp_count++;
                }
            }
    
            std::cout << "Parsed packets: IPv4=" << ipv4_count
                      << ", IPv6=" << ipv6_count
                      << ", ARP=" << arp_count
                      << ", ICMP=" << icmp_count
                      << ", TCP=" << tcp_count
                      << ", UDP=" << udp_count << std::endl;
    
            return ipv4_ipv6_packets;
        }
    };
    

    // Routing node: Modify IPv4 destination addresses
    tbb::flow::function_node<std::vector<std::array<char, PACKET_SIZE>>, std::vector<std::array<char, PACKET_SIZE>>> route_node{
        g, tbb::flow::unlimited, [&](std::vector<std::array<char, PACKET_SIZE>> packets) {
            std::vector<std::array<char, PACKET_SIZE>> ipv4_packets;
    
            for (const auto& packet : packets) {
                // Skip non-IPv4 packets
                if (!(static_cast<unsigned char>(packet[12]) == 0x08 &&
                      static_cast<unsigned char>(packet[13]) == 0x00)) {
                    continue;
                }
    
                std::cout << "Original IPv4 destination: "
                          << static_cast<int>(static_cast<unsigned char>(packet[30])) << "."
                          << static_cast<int>(static_cast<unsigned char>(packet[31])) << "."
                          << static_cast<int>(static_cast<unsigned char>(packet[32])) << "."
                          << static_cast<int>(static_cast<unsigned char>(packet[33])) << std::endl;
    
                std::array<char, PACKET_SIZE> modified_packet = packet;
    
                // Modify destination IP
                for (int i = 30; i <= 33; ++i) {
                    modified_packet[i] = static_cast<unsigned char>(modified_packet[i]) + 1;
                }
    
                std::cout << "Modified IPv4 destination: "
                          << static_cast<int>(static_cast<unsigned char>(modified_packet[30])) << "."
                          << static_cast<int>(static_cast<unsigned char>(modified_packet[31])) << "."
                          << static_cast<int>(static_cast<unsigned char>(modified_packet[32])) << "."
                          << static_cast<int>(static_cast<unsigned char>(modified_packet[33])) << std::endl;
    
                ipv4_packets.push_back(modified_packet);
            }
    
            return ipv4_packets;
        }
    };
    

    // Packet inspection node
    tbb::flow::function_node<std::vector<std::array<char, PACKET_SIZE>>, std::vector<std::array<char, PACKET_SIZE>>> inspect_packet_node{
        g, tbb::flow::unlimited, [&](std::vector<std::array<char, PACKET_SIZE>> packets) {
            {
                sycl::queue gpuQ;
                try {
                    gpuQ = sycl::queue(sycl::gpu_selector_v, dpc_common::exception_handler);
                } catch (const sycl::exception& e) {
                    gpuQ = sycl::queue(sycl::cpu_selector_v, dpc_common::exception_handler);
                }

                // Allocate USM memory for the packets
                char* usm_packets = sycl::malloc_shared<char>(packets.size() * PACKET_SIZE, gpuQ);

                // Copy data from host to USM
                for (size_t i = 0; i < packets.size(); ++i) {
                    std::memcpy(usm_packets + i * PACKET_SIZE, packets[i].data(), PACKET_SIZE);
                }

                // Submit a single kernel to process all packets
                gpuQ.submit([&](sycl::handler& h) {
                    h.parallel_for(sycl::range<2>(packets.size(), PACKET_SIZE), [=](sycl::id<2> idx) {
                        size_t packet_idx = idx[0]; // Packet index
                        size_t byte_idx = idx[1];   // Byte index within the packet
                        usm_packets[packet_idx * PACKET_SIZE + byte_idx] += 1; // Example operation: increment each byte
                    });
                });

                // Wait for all GPU operations to complete
                gpuQ.wait_and_throw();

                // Copy data back from USM to host
                for (size_t i = 0; i < packets.size(); ++i) {
                    std::memcpy(packets[i].data(), usm_packets + i * PACKET_SIZE, PACKET_SIZE);
                }

                // Free USM memory
                sycl::free(usm_packets, gpuQ);
            }

            // Forward the packets to the next node
            return packets;
        }
    };

    // Send node: Send packets over a raw socket
    tbb::flow::function_node<std::vector<std::array<char, PACKET_SIZE>>> send_node{
        g, tbb::flow::unlimited, [&](std::vector<std::array<char, PACKET_SIZE>> packets) {
            std::cout << "Sending " << packets.size() << " packets" << std::endl;

            // Create a raw socket
            int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
            if (sock < 0) {
                perror("Socket creation failed");
                return;
            }

            // Configure the destination interface
            struct sockaddr_ll dest_addr;
            std::memset(&dest_addr, 0, sizeof(dest_addr));
            dest_addr.sll_family = AF_PACKET;
            dest_addr.sll_protocol = htons(ETH_P_ALL);
            dest_addr.sll_ifindex = if_nametoindex("eth0");
            if (dest_addr.sll_ifindex == 0) {
                perror("Failed to get interface index");
                close(sock);
                return;
            }

            for (const auto& packet : packets) {
                // Send the packet over the raw socket
                ssize_t sent_bytes = sendto(sock, packet.data(), PACKET_SIZE, 0,
                                            (struct sockaddr*)&dest_addr, sizeof(dest_addr));
                if (sent_bytes < 0) {
                    perror("Failed to send packet");
                } else {
                    std::cout << "Packet sent: ";
                    for (size_t i = 0; i < std::min<size_t>(10, PACKET_SIZE); ++i) {
                        std::cout << std::hex << static_cast<int>(static_cast<unsigned char>(packet[i])) << " ";
                    }
                    std::cout << std::dec << std::endl;
                }
            }

            // Close the socket
            close(sock);
        }
    };

    // Construct the graph
    tbb::flow::make_edge(in_node, parse_node);
    tbb::flow::make_edge(parse_node, route_node);
    tbb::flow::make_edge(route_node, inspect_packet_node);
    tbb::flow::make_edge(inspect_packet_node, send_node);

    in_node.activate();
    g.wait_for_all();

    std::cout << "Done waiting" << std::endl;
}