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

const size_t burst_size = 32;
#define PACKET_SIZE 64

int main() {
    sycl::queue q;

    std::cout << "Using device: " <<
        q.get_device().get_info<sycl::info::device::name>() << std::endl;

    int nth = 10;  // number of threads
    auto mp = tbb::global_control::max_allowed_parallelism;
    tbb::global_control gc(mp, nth);
    tbb::flow::graph g;

    // Input node: get packets from the socket or from the packet capture
    tbb::flow::input_node<std::vector<std::array<char, PACKET_SIZE>>> in_node{g,
        [&](tbb::flow_control& fc) -> std::vector<std::array<char, PACKET_SIZE>> {
            static pcap_t* handle = nullptr;
            static char errbuf[PCAP_ERRBUF_SIZE];

            if (!handle) {
                handle = pcap_open_offline("/root/keysight-challenge-2025/src/capture2.pcap", errbuf);
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
            std::vector<std::array<char, PACKET_SIZE>> ipv4_packets;
            size_t ipv4_count = 0, ipv6_count = 0, arp_count = 0;

            for (const auto& packet : packets) {
                // Check EtherType field (bytes 12 and 13 in Ethernet header)
                if (static_cast<unsigned char>(packet[12]) == 0x08 && static_cast<unsigned char>(packet[13]) == 0x00) { // IPv4 EtherType
                    ipv4_packets.push_back(packet);
                    ipv4_count++;
                } else if (static_cast<unsigned char>(packet[12]) == 0x86 && static_cast<unsigned char>(packet[13]) == 0xDD) { // IPv6 EtherType
                    ipv6_count++;
                } else if (static_cast<unsigned char>(packet[12]) == 0x08 && static_cast<unsigned char>(packet[13]) == 0x06) { // ARP EtherType
                    arp_count++;
                }
            }

            // Log the counts
            std::cout << "Parsed " << ipv4_count << " IPv4 packets, "
                      << ipv6_count << " IPv6 packets, "
                      << arp_count << " ARP packets" << std::endl;

            // Return only IPv4 packets for further processing
            return ipv4_packets;
        }
    };

    // Routing node: Modify IPv4 destination addresses
    tbb::flow::function_node<std::vector<std::array<char, PACKET_SIZE>>, std::vector<std::array<char, PACKET_SIZE>>> route_node{
        g, tbb::flow::unlimited, [&](std::vector<std::array<char, PACKET_SIZE>> packets) {
            for (auto& packet : packets) {
                // Extract and log the original IPv4 destination address
                std::cout << "Original IPv4 destination: "
                          << static_cast<int>(static_cast<unsigned char>(packet[30])) << "."
                          << static_cast<int>(static_cast<unsigned char>(packet[31])) << "."
                          << static_cast<int>(static_cast<unsigned char>(packet[32])) << "."
                          << static_cast<int>(static_cast<unsigned char>(packet[33])) << std::endl;

                // Modify the IPv4 destination address by adding 1 to each byte
                for (int i = 30; i <= 33; ++i) {
                    packet[i] = static_cast<unsigned char>(packet[i]) + 1;
                }

                // Log the modified IPv4 destination address
                std::cout << "Modified IPv4 destination: "
                          << static_cast<int>(static_cast<unsigned char>(packet[30])) << "."
                          << static_cast<int>(static_cast<unsigned char>(packet[31])) << "."
                          << static_cast<int>(static_cast<unsigned char>(packet[32])) << "."
                          << static_cast<int>(static_cast<unsigned char>(packet[33])) << std::endl;
            }

            // Return the modified packets
            return packets;
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

                gpuQ.submit([&](sycl::handler& h) {
                    auto compute = [=](auto i) {
                        // Process the packets (e.g., perform GPU computations)
                    };

                    h.parallel_for(packets.size(), compute);
                }).wait_and_throw();
            }

            // Forward the packets to the next node
            return packets;
        }
    };

    // Send node: Simulate sending packets
    tbb::flow::function_node<std::vector<std::array<char, PACKET_SIZE>>> send_node{
        g, tbb::flow::unlimited, [&](std::vector<std::array<char, PACKET_SIZE>> packets) {
            std::cout << "Sending " << packets.size() << " packets" << std::endl;

            for (const auto& packet : packets) {
                // Simulate sending the packet (e.g., log or write to a socket)
                // For now, just log the first few bytes of the packet
                std::cout << "Packet sent: ";
                for (size_t i = 0; i < std::min<size_t>(10, PACKET_SIZE); ++i) {
                    std::cout << std::hex << static_cast<int>(static_cast<unsigned char>(packet[i])) << " ";
                }
                std::cout << std::dec << std::endl;
            }
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
